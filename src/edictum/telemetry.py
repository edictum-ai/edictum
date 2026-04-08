"""OpenTelemetry integration — graceful no-op if absent."""

from __future__ import annotations

from typing import Any

try:
    from opentelemetry import metrics, trace

    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False


class _NoOpSpan:
    """Dummy span when OTel is not available."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key, value):
        pass

    def set_status(self, status, description=None):
        pass

    def add_event(self, name, attributes=None):
        pass

    def end(self):
        pass


class GovernanceTelemetry:
    """OTel integration for rule evaluation. No-op if opentelemetry not installed.

    Install: pip install edictum[otel]
    """

    def __init__(self):
        if _HAS_OTEL:
            self._tracer = trace.get_tracer("edictum")
            self._meter = metrics.get_meter("edictum")
            self._setup_metrics()
        else:
            self._tracer = None
            self._meter = None

    def _setup_metrics(self):
        if not self._meter:
            return
        self._denied_counter = self._meter.create_counter(
            "edictum.calls.blocked",
            description="Number of blocked tool calls",
        )
        self._allowed_counter = self._meter.create_counter(
            "edictum.calls.allowed",
            description="Number of allowed tool calls",
        )

    def start_tool_span(self, tool_call: Any) -> Any:
        """Start span. Returns _NoOpSpan if OTel not available."""
        if not self._tracer:
            return _NoOpSpan()
        return self._tracer.start_span(
            f"tool.execute {tool_call.tool_name}",
            attributes={
                "tool.name": tool_call.tool_name,
                "tool.side_effect": tool_call.side_effect.value,
                "tool.call_index": tool_call.call_index,
                "governance.environment": tool_call.environment,
                "governance.run_id": tool_call.run_id,
            },
        )

    def record_denial(self, tool_call: Any, reason: str | None = None) -> None:
        if _HAS_OTEL and self._meter:
            self._denied_counter.add(1, {"tool.name": tool_call.tool_name})

    def record_allowed(self, tool_call: Any) -> None:
        if _HAS_OTEL and self._meter:
            self._allowed_counter.add(1, {"tool.name": tool_call.tool_name})

    def set_span_error(self, span: Any, reason: str) -> None:
        """Set span status to ERROR. No-op if OTel not available."""
        if not _HAS_OTEL:
            return
        from opentelemetry.trace import StatusCode

        span.set_status(StatusCode.ERROR, reason)

    def set_span_ok(self, span: Any) -> None:
        """Set span status to OK. No-op if OTel not available."""
        if not _HAS_OTEL:
            return
        from opentelemetry.trace import StatusCode

        span.set_status(StatusCode.OK)

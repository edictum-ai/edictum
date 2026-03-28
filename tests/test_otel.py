"""Tests for OpenTelemetry integration."""

from __future__ import annotations

import json

import pytest


def test_otel_import_without_deps():
    """OTel module should import without opentelemetry installed."""
    from edictum.otel import has_otel

    # has_otel() depends on whether otel is installed in test env
    assert isinstance(has_otel(), bool)


def test_noop_span():
    """NoOpSpan should accept all method calls silently."""
    from edictum.otel import _NoOpSpan

    span = _NoOpSpan()
    span.set_attribute("key", "value")
    span.set_status("OK")
    span.set_status("ERROR", "some description")
    span.add_event("test", {"key": "value"})
    span.end()
    assert span.get_span_context() is None
    with span:
        pass


def test_noop_tracer():
    """NoOpTracer should return NoOpSpan."""
    from edictum.otel import _NoOpSpan, _NoOpTracer

    tracer = _NoOpTracer()
    span = tracer.start_span("test")
    assert isinstance(span, _NoOpSpan)
    span.end()


def test_noop_tracer_context_manager():
    """NoOpTracer.start_as_current_span should work as context manager."""
    from edictum.otel import _NoOpSpan, _NoOpTracer

    tracer = _NoOpTracer()
    with tracer.start_as_current_span("test") as span:
        assert isinstance(span, _NoOpSpan)
        span.set_attribute("key", "value")


def test_get_tracer_returns_something():
    """get_tracer should return a tracer (real or no-op)."""
    from edictum.otel import get_tracer

    tracer = get_tracer("test")
    assert hasattr(tracer, "start_span")
    assert hasattr(tracer, "start_as_current_span")


# If OTel IS installed in test env, add integration tests
try:
    import opentelemetry

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


if HAS_OTEL:
    import threading

    from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

    class _InMemoryExporter(SpanExporter):
        """Minimal in-memory exporter for tests (not shipped in OTel SDK 1.39+)."""

        def __init__(self):
            self._spans = []
            self._lock = threading.Lock()

        def export(self, spans):
            with self._lock:
                self._spans.extend(spans)
            return SpanExportResult.SUCCESS

        def shutdown(self):
            pass

        def force_flush(self, timeout_millis=None):
            return True

        def get_finished_spans(self):
            with self._lock:
                return list(self._spans)

        def clear(self):
            with self._lock:
                self._spans.clear()

    def _reset_otel_provider():
        """Reset the global OTel tracer provider so tests can install their own."""
        from opentelemetry import trace
        from opentelemetry.util._once import Once

        trace._TRACER_PROVIDER_SET_ONCE = Once()
        trace._TRACER_PROVIDER = trace._PROXY_TRACER_PROVIDER


class _NullAuditSink:
    """Audit sink that silently discards events."""

    async def emit(self, event):
        pass


@pytest.mark.skipif(not HAS_OTEL, reason="OpenTelemetry not installed")
class TestOTelIntegration:
    def _setup_exporter(self):
        """Create a fresh TracerProvider + InMemoryExporter pair.

        Resets the global provider first so each test gets a clean slate.
        """
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        _reset_otel_provider()

        exporter = _InMemoryExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        return exporter

    def test_configure_otel(self):
        """configure_otel should set up tracer provider."""
        from edictum.otel import configure_otel, has_otel

        _reset_otel_provider()

        assert has_otel()
        # Should not raise
        configure_otel(service_name="test-agent", endpoint="http://localhost:4317")

    def test_configure_otel_skips_if_provider_set(self):
        """configure_otel should no-op when a TracerProvider already exists."""
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        from edictum.otel import configure_otel

        _reset_otel_provider()

        # Pre-install a provider (simulating host app setup)
        existing = TracerProvider()
        trace.set_tracer_provider(existing)

        # configure_otel should skip because provider already set
        configure_otel(service_name="should-not-apply")

        # Provider should still be the original one
        assert trace.get_tracer_provider() is existing

    def test_configure_otel_force_overrides_existing(self):
        """configure_otel(force=True) should replace an existing provider."""
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        from edictum.otel import configure_otel

        _reset_otel_provider()

        existing = TracerProvider()
        trace.set_tracer_provider(existing)

        _reset_otel_provider()
        configure_otel(service_name="forced-agent", force=True)

        # Provider should have been replaced
        current = trace.get_tracer_provider()
        assert isinstance(current, TracerProvider)
        assert current is not existing

    def test_configure_otel_env_overrides(self, monkeypatch):
        """Env vars should take precedence over function arguments."""
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        from edictum.otel import configure_otel

        _reset_otel_provider()

        monkeypatch.setenv("OTEL_SERVICE_NAME", "env-service")
        monkeypatch.setenv("OTEL_RESOURCE_ATTRIBUTES", "team=platform,env=staging")

        configure_otel(service_name="arg-service")

        provider = trace.get_tracer_provider()
        assert isinstance(provider, TracerProvider)
        resource = provider.resource
        # Env var should win over argument
        assert resource.attributes.get("service.name") == "env-service"
        assert resource.attributes.get("team") == "platform"
        assert resource.attributes.get("env") == "staging"

    def test_configure_otel_protocol_env(self, monkeypatch):
        """OTEL_EXPORTER_OTLP_PROTOCOL should override the protocol arg."""
        from edictum.otel import configure_otel

        _reset_otel_provider()

        # Set protocol to http via env — configure_otel should pick it up
        # (we just verify it doesn't crash; actual exporter wiring is internal)
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http")
        configure_otel(protocol="grpc")

    def test_configure_otel_http_protobuf_protocol(self):
        """'http/protobuf' should be accepted and select the HTTP exporter."""
        from edictum.otel import configure_otel

        _reset_otel_provider()

        # Should not raise — http/protobuf is a common OTEL_EXPORTER_OTLP_PROTOCOL value
        configure_otel(protocol="http/protobuf")

    def test_http_protocol_adjusts_default_endpoint(self):
        """HTTP protocol with default endpoint should auto-adjust to port 4318."""
        import unittest.mock as mock

        from edictum.otel import configure_otel

        _reset_otel_provider()

        with mock.patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter") as mock_http:
            mock_http.return_value = mock.MagicMock()
            configure_otel(protocol="http")
            mock_http.assert_called_once_with(endpoint="http://localhost:4318/v1/traces")

    def test_http_protocol_preserves_custom_endpoint(self):
        """HTTP protocol with explicit endpoint should not auto-adjust."""
        import unittest.mock as mock

        from edictum.otel import configure_otel

        _reset_otel_provider()

        with mock.patch("opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter") as mock_http:
            mock_http.return_value = mock.MagicMock()
            configure_otel(protocol="http", endpoint="http://collector:4318/v1/traces")
            mock_http.assert_called_once_with(endpoint="http://collector:4318/v1/traces")

    def test_span_attributes(self):
        """Spans should carry edictum-specific attributes."""
        from opentelemetry import trace

        exporter = self._setup_exporter()
        tracer = trace.get_tracer("edictum")

        with tracer.start_as_current_span("edictum.evaluate") as span:
            span.set_attribute("edictum.rule.id", "restrict-patient-access")
            span.set_attribute("edictum.decision", "block")
            span.set_attribute("edictum.tool.name", "query_patient_records")
            span.set_attribute("edictum.principal.role", "researcher")

        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        assert spans[0].name == "edictum.evaluate"
        assert spans[0].attributes["edictum.rule.id"] == "restrict-patient-access"
        assert spans[0].attributes["edictum.decision"] == "block"

        exporter.clear()

    def test_pii_not_in_spans(self):
        """PII should be masked before being set as span attributes."""
        from edictum.audit import RedactionPolicy

        exporter = self._setup_exporter()
        tracer = opentelemetry.trace.get_tracer("edictum")

        policy = RedactionPolicy()
        raw_args = {"name": "John", "api_key": "sk-abc123xyz456789012345"}
        redacted = policy.redact_args(raw_args)

        with tracer.start_as_current_span("edictum.evaluate") as span:
            span.set_attribute("edictum.tool.args", json.dumps(redacted))

        spans = exporter.get_finished_spans()
        args_str = spans[0].attributes["edictum.tool.args"]
        assert "sk-abc123xyz456789012345" not in args_str
        assert "[REDACTED]" in args_str

        exporter.clear()

    def test_trace_context_propagation(self):
        """Edictum spans should be children of existing spans."""
        from opentelemetry import trace

        exporter = self._setup_exporter()
        tracer = trace.get_tracer("edictum")
        framework_tracer = trace.get_tracer("langchain")

        with framework_tracer.start_as_current_span("langchain.agent_run") as parent:  # noqa: F841
            with tracer.start_as_current_span("edictum.envelope") as child:
                child.set_attribute("edictum.tool.name", "query")
                with tracer.start_as_current_span("edictum.evaluate") as eval_span:
                    eval_span.set_attribute("edictum.decision", "allow")

        spans = exporter.get_finished_spans()
        assert len(spans) == 3

        parent_span = [s for s in spans if s.name == "langchain.agent_run"][0]
        tool_span = [s for s in spans if s.name == "edictum.envelope"][0]
        eval_span = [s for s in spans if s.name == "edictum.evaluate"][0]

        assert tool_span.parent.span_id == parent_span.context.span_id
        assert eval_span.parent.span_id == tool_span.context.span_id

        exporter.clear()

    async def test_governance_span_emitted_on_allow(self):
        """When a tool call is allowed, governance spans should be emitted."""
        from edictum import Edictum

        exporter = self._setup_exporter()

        guard = Edictum(mode="enforce", audit_sink=_NullAuditSink())
        result = await guard.run(
            "TestTool",
            {"arg1": "value1"},
            lambda **kw: "ok",
        )
        assert result == "ok"

        spans = exporter.get_finished_spans()
        gov_spans = [s for s in spans if s.name == "edictum.evaluate"]
        assert len(gov_spans) >= 1

        # At least one governance span should reference the tool
        tool_name_spans = [s for s in gov_spans if s.attributes.get("edictum.tool.name") == "TestTool"]
        assert len(tool_name_spans) >= 1

        exporter.clear()

    async def test_governance_span_on_deny(self):
        """When a tool call is denied, governance span should have ERROR status."""
        from opentelemetry.trace import StatusCode

        from edictum import Edictum, EdictumDenied, precondition
        from edictum.rules import Decision
        from edictum.envelope import ToolCall

        exporter = self._setup_exporter()

        @precondition(tool="DangerousTool")
        def block_dangerous(tool_call: ToolCall) -> Decision:
            return Decision.fail("Tool is too dangerous")

        guard = Edictum(
            mode="enforce",
            rules=[block_dangerous],
            audit_sink=_NullAuditSink(),
        )

        with pytest.raises(EdictumDenied):
            await guard.run(
                "DangerousTool",
                {},
                lambda **kw: "should not reach",
            )

        spans = exporter.get_finished_spans()
        gov_spans = [s for s in spans if s.name == "edictum.evaluate"]
        assert len(gov_spans) >= 1

        denied_spans = [s for s in gov_spans if s.attributes.get("edictum.decision") == "call_denied"]
        assert len(denied_spans) >= 1
        assert denied_spans[0].status.status_code == StatusCode.ERROR

        exporter.clear()

    async def test_session_counters_never_none(self):
        """Session counters should default to 0, never None in span attributes."""
        from edictum import Edictum

        exporter = self._setup_exporter()

        guard = Edictum(mode="enforce", audit_sink=_NullAuditSink())
        await guard.run("SomeTool", {}, lambda **kw: "ok")

        spans = exporter.get_finished_spans()
        gov_spans = [s for s in spans if s.name == "edictum.evaluate"]
        assert len(gov_spans) >= 1

        for span in gov_spans:
            attempt = span.attributes.get("edictum.session.attempt_count")
            execution = span.attributes.get("edictum.session.execution_count")
            assert attempt is not None, "attempt_count should never be None"
            assert execution is not None, "execution_count should never be None"
            assert isinstance(attempt, int)
            assert isinstance(execution, int)

        exporter.clear()

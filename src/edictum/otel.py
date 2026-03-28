"""Edictum OpenTelemetry integration.

Emits governance-specific spans for every rule evaluation.
Gracefully degrades to no-op if OpenTelemetry is not installed.

Install: pip install edictum[otel]
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    _HAS_OTEL = True
except ImportError:
    _HAS_OTEL = False


def has_otel() -> bool:
    """Check if OpenTelemetry is available."""
    return _HAS_OTEL


def _is_provider_configured() -> bool:
    """Check whether a non-default TracerProvider is already set."""
    if not _HAS_OTEL:
        return False
    current = trace.get_tracer_provider()
    # The proxy provider wraps the real one; if it's still a proxy,
    # no SDK provider has been configured yet.
    return isinstance(current, TracerProvider)


def configure_otel(
    *,
    service_name: str = "edictum-agent",
    endpoint: str = "http://localhost:4317",
    protocol: str = "grpc",
    resource_attributes: dict[str, str] | None = None,
    edictum_version: str | None = None,
    force: bool = False,
    insecure: bool = True,
) -> None:
    """Configure OpenTelemetry for Edictum.

    Call this once at startup to enable OTel span emission.
    If OTel is not installed, this is a no-op.

    If a TracerProvider is already configured (e.g. by the host
    application), this function is a no-op unless *force=True*.
    This prevents Edictum from clobbering an existing OTel setup.

    *protocol* accepts ``"grpc"`` (default), ``"http"``, or
    ``"http/protobuf"``.  Any value other than ``"grpc"`` selects the
    HTTP exporter.  When the HTTP exporter is selected and *endpoint*
    is still the default (``http://localhost:4317``), the endpoint is
    automatically adjusted to ``http://localhost:4318/v1/traces``.

    *insecure* controls TLS for the gRPC exporter. ``True`` (default)
    sends spans over plaintext; set to ``False`` for TLS-enabled
    collectors. Has no action on the HTTP exporter (use ``https://``
    in *endpoint* instead).

    Standard OTel env vars take precedence over arguments:
    - OTEL_SERVICE_NAME overrides *service_name*
    - OTEL_EXPORTER_OTLP_ENDPOINT overrides *endpoint*
    - OTEL_EXPORTER_OTLP_PROTOCOL overrides *protocol*
    - OTEL_RESOURCE_ATTRIBUTES merged with *resource_attributes*
    """
    if not _HAS_OTEL:
        return

    if _is_provider_configured() and not force:
        return

    # Env overrides
    actual_service = os.environ.get("OTEL_SERVICE_NAME", service_name)
    actual_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
    actual_protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", protocol)

    # Normalize protocol: "http/protobuf" and "http" both mean HTTP
    use_grpc = actual_protocol == "grpc"

    # Adjust default endpoint for HTTP when the caller didn't override it
    if not use_grpc and actual_endpoint == "http://localhost:4317":
        actual_endpoint = "http://localhost:4318/v1/traces"

    # Build resource attributes — env OTEL_RESOURCE_ATTRIBUTES merged last
    attrs: dict[str, str] = {
        "service.name": actual_service,
    }
    if edictum_version:
        attrs["edictum.version"] = edictum_version
    if resource_attributes:
        attrs.update(resource_attributes)

    env_attrs = os.environ.get("OTEL_RESOURCE_ATTRIBUTES", "")
    if env_attrs:
        for pair in env_attrs.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                attrs[k.strip()] = v.strip()

    resource = Resource.create(attrs)
    provider = TracerProvider(resource=resource)

    if use_grpc:
        exporter = OTLPSpanExporter(endpoint=actual_endpoint, insecure=insecure)
    else:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter as HTTPExporter

        exporter = HTTPExporter(endpoint=actual_endpoint)

    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


def get_tracer(name: str = "edictum") -> Any:
    """Get an OTel tracer. Returns no-op if OTel not installed."""
    if not _HAS_OTEL:
        return _NoOpTracer()
    return trace.get_tracer(name)


class _NoOpSpan:
    """Dummy span when OTel is not available."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, status: Any, description: str | None = None) -> None:
        pass

    def add_event(self, name: str, attributes: dict | None = None) -> None:
        pass

    def end(self) -> None:
        pass

    def get_span_context(self) -> None:
        return None


class _NoOpTracer:
    """Dummy tracer when OTel is not available."""

    def start_span(self, name: str, **kwargs: Any) -> _NoOpSpan:
        return _NoOpSpan()

    def start_as_current_span(self, name: str, **kwargs: Any) -> contextlib._GeneratorContextManager:
        @contextlib.contextmanager
        def _noop_ctx():
            yield _NoOpSpan()

        return _noop_ctx()

"""Behavior tests for audit sinks — CompositeSink and list auto-wrapping."""

from __future__ import annotations

import pytest

from edictum import Edictum
from edictum.audit import (
    AuditAction,
    AuditEvent,
    AuditSink,
    CompositeSink,
)


class _CaptureSink:
    """Minimal AuditSink that records emitted events."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class TestCompositeSinkBehavior:
    """CompositeSink fans out events to every wrapped sink."""

    async def test_events_reach_all_sinks(self):
        sink_a = _CaptureSink()
        sink_b = _CaptureSink()
        composite = CompositeSink([sink_a, sink_b])

        event = AuditEvent(action=AuditAction.CALL_ALLOWED, tool_name="Read")
        await composite.emit(event)

        assert len(sink_a.events) == 1
        assert len(sink_b.events) == 1
        assert sink_a.events[0] is event
        assert sink_b.events[0] is event

    async def test_multiple_events_accumulate_in_all_sinks(self):
        sink_a = _CaptureSink()
        sink_b = _CaptureSink()
        composite = CompositeSink([sink_a, sink_b])

        for i in range(3):
            await composite.emit(AuditEvent(action=AuditAction.CALL_ALLOWED, tool_name=f"tool_{i}"))

        assert len(sink_a.events) == 3
        assert len(sink_b.events) == 3

    async def test_sinks_property_returns_copy(self):
        sink_a = _CaptureSink()
        composite = CompositeSink([sink_a])
        returned = composite.sinks
        returned.append(_CaptureSink())
        assert len(composite.sinks) == 1

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="at least one sink"):
            CompositeSink([])

    async def test_conforms_to_audit_sink_protocol(self):
        composite = CompositeSink([_CaptureSink()])
        assert isinstance(composite, AuditSink)


class TestEdictumListAutoWrap:
    """Passing a list of sinks to Edictum auto-wraps in CompositeSink."""

    async def test_list_wraps_in_composite(self):
        sink_a = _CaptureSink()
        sink_b = _CaptureSink()
        guard = Edictum(audit_sink=[sink_a, sink_b])

        assert isinstance(guard.audit_sink, CompositeSink)
        # local_sink is always first, then user-provided sinks
        assert guard.audit_sink.sinks[0] is guard.local_sink
        assert guard.audit_sink.sinks[1] is sink_a
        assert guard.audit_sink.sinks[2] is sink_b

    async def test_single_sink_wraps_in_composite(self):
        sink = _CaptureSink()
        guard = Edictum(audit_sink=sink)

        assert isinstance(guard.audit_sink, CompositeSink)
        assert sink in guard.audit_sink.sinks

    async def test_none_defaults_to_local_sink_only(self):
        guard = Edictum()
        assert guard.audit_sink is guard.local_sink

    async def test_list_sinks_receive_events_through_run(self):
        sink_a = _CaptureSink()
        sink_b = _CaptureSink()
        guard = Edictum(audit_sink=[sink_a, sink_b])

        await guard.run("read_file", {"path": "/tmp/test"}, lambda **kw: "ok")

        assert len(sink_a.events) >= 2  # pre + post audit events
        assert len(sink_b.events) >= 2
        assert len(sink_a.events) == len(sink_b.events)

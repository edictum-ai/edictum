"""Behavior tests for AuditEvent lineage fields."""

from __future__ import annotations

import json

import pytest

from edictum import Edictum
from edictum.audit import AuditAction, AuditEvent, StdoutAuditSink
from edictum.storage import MemoryBackend


class TestAuditLineageBehavior:
    """AuditEvent lineage parameters change emitted payloads."""

    async def test_session_id_changes_stdout_payload(self, capsys):
        sink = StdoutAuditSink()

        await sink.emit(
            AuditEvent(
                action=AuditAction.CALL_ALLOWED,
                tool_name="Read",
                session_id="session-123",
            )
        )

        payload = json.loads(capsys.readouterr().out)
        assert payload["session_id"] == "session-123"

    async def test_parent_session_id_changes_stdout_payload(self, capsys):
        sink = StdoutAuditSink()

        await sink.emit(
            AuditEvent(
                action=AuditAction.CALL_ALLOWED,
                tool_name="Read",
                parent_session_id="parent-456",
            )
        )

        payload = json.loads(capsys.readouterr().out)
        assert payload["parent_session_id"] == "parent-456"

    @pytest.mark.asyncio
    async def test_run_emits_audit_events_with_session_id(self):
        guard = Edictum(backend=MemoryBackend())

        await guard.run("Read", {"path": "spec.md"}, lambda path: "ok", session_id="session-789")

        assert len(guard.local_sink.events) >= 2
        assert {event.session_id for event in guard.local_sink.events} == {"session-789"}

"""Behavior tests for session lineage fields on AuditEvent and ApprovalRequest."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, asdict

import pytest

from edictum.approval import ApprovalRequest
from edictum.audit import (
    AuditAction,
    AuditEvent,
    FileAuditSink,
    StdoutAuditSink,
)


class TestAuditEventSessionLineage:
    """AuditEvent carries optional session_id and parent_session_id."""

    def test_defaults_to_none(self):
        event = AuditEvent()
        assert event.session_id is None
        assert event.parent_session_id is None

    def test_session_id_set(self):
        event = AuditEvent(session_id="sess-001")
        assert event.session_id == "sess-001"
        assert event.parent_session_id is None

    def test_parent_session_id_set(self):
        event = AuditEvent(
            session_id="sess-child",
            parent_session_id="sess-parent",
        )
        assert event.session_id == "sess-child"
        assert event.parent_session_id == "sess-parent"

    def test_serializes_in_asdict(self):
        event = AuditEvent(
            session_id="sess-001",
            parent_session_id="sess-parent",
            action=AuditAction.CALL_ALLOWED,
        )
        data = asdict(event)
        assert data["session_id"] == "sess-001"
        assert data["parent_session_id"] == "sess-parent"

    def test_none_values_serialize(self):
        event = AuditEvent()
        data = asdict(event)
        assert data["session_id"] is None
        assert data["parent_session_id"] is None


class TestAuditEventSessionLineageSinks:
    """Sinks serialize session lineage fields."""

    async def test_stdout_sink_includes_session_id(self, capsys):
        sink = StdoutAuditSink()
        event = AuditEvent(
            action=AuditAction.CALL_ALLOWED,
            tool_name="Read",
            session_id="sess-stdout",
            parent_session_id="sess-parent-stdout",
        )
        await sink.emit(event)
        data = json.loads(capsys.readouterr().out)
        assert data["session_id"] == "sess-stdout"
        assert data["parent_session_id"] == "sess-parent-stdout"

    async def test_file_sink_includes_session_id(self, tmp_path):
        path = tmp_path / "audit.jsonl"

        sink = FileAuditSink(str(path))
        event = AuditEvent(
            action=AuditAction.CALL_EXECUTED,
            tool_name="Bash",
            session_id="sess-file",
            parent_session_id="sess-parent-file",
        )
        await sink.emit(event)

        data = json.loads(path.read_text().strip())
        assert data["session_id"] == "sess-file"
        assert data["parent_session_id"] == "sess-parent-file"


class TestApprovalRequestSessionId:
    """ApprovalRequest carries optional session_id."""

    def test_default_is_none(self):
        req = ApprovalRequest(
            approval_id="abc",
            tool_name="Bash",
            tool_args={},
            message="msg",
            timeout=60,
        )
        assert req.session_id is None

    def test_session_id_set(self):
        req = ApprovalRequest(
            approval_id="abc",
            tool_name="Bash",
            tool_args={},
            message="msg",
            timeout=60,
            session_id="sess-approval",
        )
        assert req.session_id == "sess-approval"

    def test_frozen_session_id(self):
        req = ApprovalRequest(
            approval_id="abc",
            tool_name="Bash",
            tool_args={},
            message="msg",
            timeout=60,
            session_id="sess-frozen",
        )
        with pytest.raises(FrozenInstanceError):
            req.session_id = "other"  # type: ignore[misc]


class TestPipelinePopulatesSessionId:
    """Pipeline evaluation populates session_id on emitted AuditEvents."""

    async def test_run_populates_session_id_on_audit_events(self):
        from edictum._guard import Edictum
        from edictum.audit import CollectingAuditSink

        sink = CollectingAuditSink()
        guard = Edictum(audit_sink=sink)

        await guard.run(
            tool_name="Read",
            args={"path": "/tmp/test.txt"},
            tool_callable=lambda **kw: "ok",
            session_id="sess-pipeline-test",
        )

        assert len(sink.events) >= 2, "Expected at least pre and post audit events"
        for event in sink.events:
            assert event.session_id == "sess-pipeline-test", f"AuditEvent with action={event.action} missing session_id"


class TestWorkflowStateUpdatedAction:
    """AuditAction has workflow_state_updated value."""

    def test_enum_value(self):
        assert AuditAction.WORKFLOW_STATE_UPDATED.value == "workflow_state_updated"

    def test_usable_on_audit_event(self):
        event = AuditEvent(action=AuditAction.WORKFLOW_STATE_UPDATED)
        assert event.action == AuditAction.WORKFLOW_STATE_UPDATED

    def test_all_workflow_actions_present(self):
        """All three workflow audit actions exist."""
        assert hasattr(AuditAction, "WORKFLOW_STAGE_ADVANCED")
        assert hasattr(AuditAction, "WORKFLOW_COMPLETED")
        assert hasattr(AuditAction, "WORKFLOW_STATE_UPDATED")

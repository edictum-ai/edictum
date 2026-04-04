"""Tests for ServerAuditSink."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from edictum.audit import AuditAction, AuditEvent, AuditSink
from edictum.server.audit_sink import ServerAuditSink
from edictum.server.client import EdictumServerClient


@pytest.fixture
def mock_client():
    client = MagicMock(spec=EdictumServerClient)
    client.agent_id = "test-agent"
    client.env = "production"
    client.bundle_name = "default"
    client.post = AsyncMock(return_value={"accepted": 1, "duplicates": 0})
    return client


def _make_event(**overrides) -> AuditEvent:
    defaults = {
        "call_id": "call-1",
        "tool_name": "read_file",
        "action": AuditAction.CALL_ALLOWED,
        "mode": "enforce",
        "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
        "tool_args": {"path": "/tmp/test"},
        "side_effect": "read_only",
        "environment": "production",
        "principal": None,
        "decision_source": "precondition",
        "decision_name": "allow_reads",
        "reason": None,
        "policy_version": "abc123",
    }
    defaults.update(overrides)
    return AuditEvent(**defaults)


class TestServerAuditSink:
    @pytest.mark.asyncio
    async def test_emit_single_event(self, mock_client):
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        event = _make_event()

        await sink.emit(event)
        await sink.flush()

        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "/v1/events"
        events = call_args[0][1]["events"]
        assert len(events) == 1
        assert events[0]["call_id"] == "call-1"
        assert events[0]["agent_id"] == "test-agent"
        assert events[0]["tool_name"] == "read_file"
        assert events[0]["action"] == "call_allowed"

    @pytest.mark.asyncio
    async def test_batch_flush(self, mock_client):
        sink = ServerAuditSink(mock_client, batch_size=3, flush_interval=999)

        for i in range(3):
            await sink.emit(_make_event(call_id=f"call-{i}"))

        assert mock_client.post.call_count == 1
        events = mock_client.post.call_args[0][1]["events"]
        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_event_mapping(self, mock_client):
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        event = _make_event(
            call_id="call-42",
            run_id="run-42",
            call_index=7,
            parent_call_id="call-parent",
            tool_name="write_file",
            action=AuditAction.CALL_DENIED,
            mode="enforce",
            side_effect="irreversible",
            environment="staging",
            principal={"role": "admin"},
            decision_source="precondition",
            decision_name="no_writes",
            reason="Write blocked",
            policy_version="v1.0",
            hooks_evaluated=[{"name": "hook-1"}],
            contracts_evaluated=[{"id": "rule-1", "passed": False}],
            tool_success=False,
            postconditions_passed=False,
            duration_ms=123,
            error="tool failed",
            result_summary="tool failed",
            session_attempt_count=3,
            session_execution_count=2,
            policy_error=True,
            session_id="session-123",
            parent_session_id="parent-session-456",
            workflow={
                "name": "coding-guard",
                "active_stage": "local-review",
                "completed_stages": ["read-context", "implement"],
                "pending_approval": {"required": False},
            },
        )

        payload = sink._map_event(event)
        assert payload["call_id"] == "call-42"
        assert payload["run_id"] == "run-42"
        assert payload["call_index"] == 7
        assert payload["parent_call_id"] == "call-parent"
        assert payload["tool_name"] == "write_file"
        assert payload["tool_args"] == {"path": "/tmp/test"}
        assert payload["action"] == "call_blocked"
        assert payload["mode"] == "enforce"
        assert payload["side_effect"] == "irreversible"
        assert payload["environment"] == "staging"
        assert payload["principal"] == {"role": "admin"}
        assert payload["decision_source"] == "precondition"
        assert payload["decision_name"] == "no_writes"
        assert payload["reason"] == "Write blocked"
        assert payload["hooks_evaluated"] == [{"name": "hook-1"}]
        assert payload["rules_evaluated"] == [{"id": "rule-1", "passed": False}]
        assert payload["policy_version"] == "v1.0"
        assert payload["tool_success"] is False
        assert payload["postconditions_passed"] is False
        assert payload["duration_ms"] == 123
        assert payload["error"] == "tool failed"
        assert payload["result_summary"] == "tool failed"
        assert payload["session_attempt_count"] == 3
        assert payload["session_execution_count"] == 2
        assert payload["policy_error"] is True
        assert payload["session_id"] == "session-123"
        assert payload["parent_session_id"] == "parent-session-456"
        assert payload["workflow"]["name"] == "coding-guard"
        assert payload["workflow"]["active_stage"] == "local-review"
        assert payload["workflow"]["pending_approval"] == {"required": False}
        assert "payload" not in payload
        assert "decision" not in payload

    @pytest.mark.asyncio
    async def test_implements_protocol(self, mock_client):
        sink = ServerAuditSink(mock_client)
        assert isinstance(sink, AuditSink)

    @pytest.mark.asyncio
    async def test_close_flushes(self, mock_client):
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        await sink.emit(_make_event())
        await sink.close()
        assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_flush_failure_keeps_events(self, mock_client):
        mock_client.post.side_effect = Exception("network error")
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        await sink.emit(_make_event())
        await sink.flush()
        assert len(sink._buffer) == 1  # Events retained for retry

    @pytest.mark.asyncio
    async def test_buffer_cap_drops_oldest(self, mock_client):
        mock_client.post.side_effect = Exception("network error")
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999, max_buffer_size=5)
        for i in range(8):
            await sink.emit(_make_event(call_id=f"call-{i}"))
        await sink.flush()
        assert len(sink._buffer) <= 5
        # Oldest events should have been dropped
        assert sink._buffer[0]["call_id"] == "call-3"

    @pytest.mark.asyncio
    async def test_event_mapping_includes_bundle_name(self, mock_client):
        """bundle_name is not serialized into the API event payload."""
        mock_client.bundle_name = "devops-agent"
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        event = _make_event()
        mapped = sink._map_event(event)
        assert "bundle_name" not in mapped

    @pytest.mark.asyncio
    async def test_event_mapping_uses_client_env_as_fallback(self, mock_client):
        """When event has no environment, client.env is used as fallback."""
        mock_client.env = "staging"
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        event = _make_event(environment=None)
        mapped = sink._map_event(event)
        assert mapped["environment"] == "staging"

    @pytest.mark.asyncio
    async def test_event_mapping_preserves_event_environment(self, mock_client):
        """When event has environment set, it takes precedence over client.env."""
        mock_client.env = "production"
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        event = _make_event(environment="staging")
        mapped = sink._map_event(event)
        assert mapped["environment"] == "staging"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("audit_action", "wire_action"),
        [
            (AuditAction.CALL_ALLOWED, "call_allowed"),
            (AuditAction.CALL_DENIED, "call_blocked"),
            (AuditAction.CALL_WOULD_DENY, "call_would_block"),
            (AuditAction.CALL_APPROVAL_REQUESTED, "call_asked"),
            (AuditAction.CALL_APPROVAL_GRANTED, "call_approval_granted"),
            (AuditAction.CALL_APPROVAL_DENIED, "call_approval_blocked"),
            (AuditAction.CALL_APPROVAL_TIMEOUT, "call_approval_timeout"),
        ],
    )
    async def test_event_mapping_uses_current_action_values(self, mock_client, audit_action, wire_action):
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        mapped = sink._map_event(_make_event(action=audit_action))
        assert mapped["action"] == wire_action

    @pytest.mark.asyncio
    async def test_emit_upconverts_workflow_progress_events_with_snapshot_provider(self, mock_client):
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        sink._workflow_snapshot_provider = AsyncMock(
            return_value={
                "name": "coding-guard",
                "active_stage": "local-review",
                "completed_stages": ["read-context", "implement"],
                "pending_approval": {"required": False},
            }
        )
        event = _make_event(
            action=AuditAction.WORKFLOW_STAGE_ADVANCED,
            session_id="session-123",
            workflow={"stage_id": "implement", "to_stage_id": "local-review"},
        )

        await sink.emit(event)
        await sink.flush()

        payload = mock_client.post.call_args.args[1]["events"][0]
        assert payload["workflow"] == {
            "name": "coding-guard",
            "active_stage": "local-review",
            "completed_stages": ["read-context", "implement"],
            "pending_approval": {"required": False},
            "stage_id": "implement",
            "to_stage_id": "local-review",
        }
        sink._workflow_snapshot_provider.assert_awaited_once_with(event)

    @pytest.mark.asyncio
    async def test_cancellation_preserves_events(self, mock_client):
        """CancelledError during POST must not lose events from the buffer."""

        async def slow_post(*args, **kwargs):
            await asyncio.sleep(10)  # will be cancelled

        mock_client.post = slow_post
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        await sink.emit(_make_event(call_id="precious-1"))
        await sink.emit(_make_event(call_id="precious-2"))

        flush_task = asyncio.create_task(sink.flush())
        await asyncio.sleep(0)  # let flush_task start and enter slow_post
        flush_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await flush_task

        # Events must be back in the buffer, not lost
        assert len(sink._buffer) == 2
        assert sink._buffer[0]["call_id"] == "precious-1"

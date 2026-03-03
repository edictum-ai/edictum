"""Tests for ServerAuditSink."""

from __future__ import annotations

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
        assert call_args[0][0] == "/api/v1/events"
        events = call_args[0][1]["events"]
        assert len(events) == 1
        assert events[0]["call_id"] == "call-1"
        assert events[0]["agent_id"] == "test-agent"
        assert events[0]["tool_name"] == "read_file"
        assert events[0]["verdict"] == "call_allowed"

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
            tool_name="write_file",
            action=AuditAction.CALL_DENIED,
            mode="enforce",
            side_effect="irreversible",
            environment="staging",
            principal={"role": "admin"},
            decision_source="precondition",
            decision_name="no_writes",
            reason="Write denied",
            policy_version="v1.0",
        )

        await sink.emit(event)
        await sink.flush()

        payload = mock_client.post.call_args[0][1]["events"][0]
        assert payload["call_id"] == "call-42"
        assert payload["tool_name"] == "write_file"
        assert payload["verdict"] == "call_denied"
        assert payload["mode"] == "enforce"
        assert payload["payload"]["side_effect"] == "irreversible"
        assert payload["payload"]["environment"] == "staging"
        assert payload["payload"]["principal"] == {"role": "admin"}
        assert payload["payload"]["decision_source"] == "precondition"
        assert payload["payload"]["decision_name"] == "no_writes"
        assert payload["payload"]["reason"] == "Write denied"
        assert payload["payload"]["policy_version"] == "v1.0"

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
        """bundle_name from client is included in mapped event payload."""
        mock_client.bundle_name = "devops-agent"
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        event = _make_event()
        mapped = sink._map_event(event)
        assert mapped["payload"]["bundle_name"] == "devops-agent"

    @pytest.mark.asyncio
    async def test_event_mapping_uses_client_env_as_fallback(self, mock_client):
        """When event has no environment, client.env is used as fallback."""
        mock_client.env = "staging"
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        event = _make_event(environment=None)
        mapped = sink._map_event(event)
        assert mapped["payload"]["environment"] == "staging"

    @pytest.mark.asyncio
    async def test_event_mapping_preserves_event_environment(self, mock_client):
        """When event has environment set, it takes precedence over client.env."""
        mock_client.env = "production"
        sink = ServerAuditSink(mock_client, batch_size=50, flush_interval=999)
        event = _make_event(environment="staging")
        mapped = sink._map_event(event)
        assert mapped["payload"]["environment"] == "staging"

"""Tests for ServerApprovalBackend."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from edictum.approval import ApprovalBackend, ApprovalStatus
from edictum.server.approval_backend import ServerApprovalBackend
from edictum.server.client import EdictumServerClient


@pytest.fixture
def mock_client():
    client = MagicMock(spec=EdictumServerClient)
    client.agent_id = "test-agent"
    client.get = AsyncMock()
    client.post = AsyncMock()
    client.put = AsyncMock()
    return client


class TestServerApprovalBackend:
    @pytest.mark.asyncio
    async def test_request_approval(self, mock_client):
        mock_client.post.return_value = {"id": "approval-123", "status": "pending"}
        backend = ServerApprovalBackend(mock_client)

        request = await backend.request_approval(
            tool_name="delete_file",
            tool_args={"path": "/etc/config"},
            message="Approve file deletion?",
            timeout=60,
            timeout_action="block",
        )

        assert request.approval_id == "approval-123"
        assert request.tool_name == "delete_file"
        assert request.tool_args == {"path": "/etc/config"}
        assert request.message == "Approve file deletion?"
        assert request.timeout == 60
        assert request.timeout_action == "block"

        mock_client.post.assert_called_once_with(
            "/v1/approvals",
            {
                "agent_id": "test-agent",
                "tool_name": "delete_file",
                "tool_args": {"path": "/etc/config"},
                "message": "Approve file deletion?",
                "timeout": 60,
                "timeout_action": "block",
            },
        )

    @pytest.mark.asyncio
    async def test_request_approval_stores_pending(self, mock_client):
        mock_client.post.return_value = {"id": "approval-abc", "status": "pending"}
        backend = ServerApprovalBackend(mock_client)

        await backend.request_approval("tool", {}, "msg", timeout_action="allow")
        assert "approval-abc" in backend._pending
        assert backend._pending["approval-abc"].timeout_action == "allow"

    @pytest.mark.asyncio
    async def test_request_approval_preserves_session_id(self, mock_client):
        mock_client.post.return_value = {"id": "approval-session", "status": "pending"}
        backend = ServerApprovalBackend(mock_client)

        request = await backend.request_approval(
            "tool",
            {},
            "msg",
            session_id="workflow-session-123",
        )

        assert request.session_id == "workflow-session-123"
        assert backend._pending["approval-session"].session_id == "workflow-session-123"
        assert mock_client.post.call_args.args[1]["session_id"] == "workflow-session-123"

    @pytest.mark.asyncio
    async def test_wait_for_decision_approved(self, mock_client):
        mock_client.post.return_value = {"id": "approval-1", "status": "pending"}
        mock_client.get.return_value = {
            "status": "approved",
            "decided_by": "admin@example.com",
            "decision_reason": "Looks good",
        }

        backend = ServerApprovalBackend(mock_client, poll_interval=0.01)
        await backend.request_approval("tool", {}, "msg")

        decision = await backend.wait_for_decision("approval-1")
        assert decision.approved is True
        assert decision.approver == "admin@example.com"
        assert decision.reason == "Looks good"
        assert decision.status == ApprovalStatus.APPROVED

    @pytest.mark.asyncio
    async def test_wait_for_decision_rejected(self, mock_client):
        mock_client.post.return_value = {"id": "approval-2", "status": "pending"}
        mock_client.get.return_value = {
            "status": "rejected",
            "decided_by": "security@example.com",
            "decision_reason": "Too risky",
        }

        backend = ServerApprovalBackend(mock_client, poll_interval=0.01)
        await backend.request_approval("tool", {}, "msg")

        decision = await backend.wait_for_decision("approval-2")
        assert decision.approved is False
        assert decision.approver == "security@example.com"
        assert decision.reason == "Too risky"
        assert decision.status == ApprovalStatus.DENIED

    @pytest.mark.asyncio
    async def test_wait_for_decision_server_timed_out(self, mock_client):
        mock_client.post.return_value = {"id": "approval-3", "status": "pending"}
        mock_client.get.return_value = {"status": "timed_out"}

        backend = ServerApprovalBackend(mock_client, poll_interval=0.01)
        await backend.request_approval("tool", {}, "msg", timeout_action="block")

        decision = await backend.wait_for_decision("approval-3")
        assert decision.approved is False
        assert decision.status == ApprovalStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_wait_for_decision_timeout_action_allow(self, mock_client):
        mock_client.post.return_value = {"id": "approval-4", "status": "pending"}
        mock_client.get.return_value = {"status": "timed_out"}

        backend = ServerApprovalBackend(mock_client, poll_interval=0.01)
        await backend.request_approval("tool", {}, "msg", timeout_action="allow")

        decision = await backend.wait_for_decision("approval-4")
        assert decision.approved is True
        assert decision.status == ApprovalStatus.TIMEOUT

    @pytest.mark.asyncio
    async def test_wait_polls_until_resolved(self, mock_client):
        mock_client.post.return_value = {"id": "approval-5", "status": "pending"}
        mock_client.get.side_effect = [
            {"status": "pending"},
            {"status": "pending"},
            {"status": "approved", "decided_by": "admin", "decision_reason": None},
        ]

        backend = ServerApprovalBackend(mock_client, poll_interval=0.01)
        await backend.request_approval("tool", {}, "msg")

        decision = await backend.wait_for_decision("approval-5")
        assert decision.approved is True
        assert mock_client.get.call_count == 3
        mock_client.get.assert_called_with("/v1/approvals/approval-5")

    @pytest.mark.asyncio
    async def test_implements_protocol(self, mock_client):
        backend = ServerApprovalBackend(mock_client)
        assert isinstance(backend, ApprovalBackend)

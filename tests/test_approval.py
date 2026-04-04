"""Tests for the approval protocol types and LocalApprovalBackend."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from unittest.mock import patch

import pytest

from edictum.approval import (
    ApprovalBackend,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    LocalApprovalBackend,
)
from edictum.audit import AuditAction


class TestApprovalRequestFrozen:
    """ApprovalRequest is a frozen dataclass."""

    def test_frozen(self):
        req = ApprovalRequest(
            approval_id="abc",
            tool_name="Bash",
            tool_args={"command": "ls"},
            message="Approve bash?",
            timeout=60,
        )
        with pytest.raises(FrozenInstanceError):
            req.tool_name = "Other"  # type: ignore[misc]

    def test_defaults(self):
        req = ApprovalRequest(
            approval_id="abc",
            tool_name="Bash",
            tool_args={},
            message="msg",
            timeout=60,
        )
        assert req.timeout_action == "block"
        assert req.principal is None
        assert req.metadata == {}
        assert req.session_id is None
        assert req.created_at is not None


class TestApprovalDecisionFrozen:
    """ApprovalDecision is a frozen dataclass."""

    def test_frozen(self):
        dec = ApprovalDecision(approved=True)
        with pytest.raises(FrozenInstanceError):
            dec.approved = False  # type: ignore[misc]

    def test_defaults(self):
        dec = ApprovalDecision(approved=False)
        assert dec.approver is None
        assert dec.reason is None
        assert dec.status == ApprovalStatus.PENDING
        assert dec.timestamp is not None


class TestApprovalBackendProtocol:
    """ApprovalBackend is a runtime-checkable protocol."""

    def test_runtime_checkable(self):
        backend = LocalApprovalBackend()
        assert isinstance(backend, ApprovalBackend)

    def test_non_conforming_not_instance(self):
        class NotABackend:
            pass

        assert not isinstance(NotABackend(), ApprovalBackend)


class TestLocalApprovalBackendRequestApproval:
    """LocalApprovalBackend.request_approval() returns a valid ApprovalRequest."""

    async def test_returns_approval_request(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval(
            "Bash",
            {"command": "rm -rf /"},
            "Dangerous command detected",
            timeout=120,
        )
        assert isinstance(req, ApprovalRequest)
        assert req.tool_name == "Bash"
        assert req.tool_args == {"command": "rm -rf /"}
        assert req.message == "Dangerous command detected"
        assert req.timeout == 120
        assert len(req.approval_id) > 0

    async def test_generates_unique_ids(self):
        backend = LocalApprovalBackend()
        req1 = await backend.request_approval("T1", {}, "msg1")
        req2 = await backend.request_approval("T2", {}, "msg2")
        assert req1.approval_id != req2.approval_id

    async def test_stores_pending_request(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval("T1", {}, "msg")
        assert req.approval_id in backend._pending

    async def test_passes_optional_params(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval(
            "Tool",
            {"a": 1},
            "msg",
            timeout_action="allow",
            principal={"role": "admin"},
            metadata={"ticket": "T-123"},
        )
        assert req.timeout_action == "allow"
        assert req.principal == {"role": "admin"}
        assert req.metadata == {"ticket": "T-123"}

    async def test_passes_session_id(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval(
            "Tool",
            {"a": 1},
            "msg",
            session_id="workflow-session-123",
        )
        assert req.session_id == "workflow-session-123"


class TestLocalApprovalBackendTimeout:
    """Timeout handling in wait_for_decision."""

    async def test_timeout_deny(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval("Tool", {}, "msg", timeout=1, timeout_action="block")

        def _block(approval_id):
            import time

            time.sleep(10)

        with patch.object(backend, "_read_stdin", side_effect=_block):
            decision = await backend.wait_for_decision(req.approval_id, timeout=0.05)
        assert decision.approved is False
        assert decision.status == ApprovalStatus.TIMEOUT

    async def test_timeout_allow(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval("Tool", {}, "msg", timeout=1, timeout_action="allow")

        def _block(approval_id):
            import time

            time.sleep(10)

        with patch.object(backend, "_read_stdin", side_effect=_block):
            decision = await backend.wait_for_decision(req.approval_id, timeout=0.05)
        assert decision.approved is True
        assert decision.status == ApprovalStatus.TIMEOUT


class TestLocalApprovalBackendStdinResponse:
    """Stdin responses produce correct ApprovalDecision."""

    async def test_approve_yes(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval("Tool", {}, "msg")

        with patch.object(backend, "_read_stdin", return_value="y"):
            decision = await backend.wait_for_decision(req.approval_id)
        assert decision.approved is True
        assert decision.status == ApprovalStatus.APPROVED
        assert decision.approver == "local"

    async def test_approve_full_word(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval("Tool", {}, "msg")

        with patch.object(backend, "_read_stdin", return_value="yes"):
            decision = await backend.wait_for_decision(req.approval_id)
        assert decision.approved is True

    async def test_deny_no(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval("Tool", {}, "msg")

        with patch.object(backend, "_read_stdin", return_value="n"):
            decision = await backend.wait_for_decision(req.approval_id)
        assert decision.approved is False
        assert decision.status == ApprovalStatus.DENIED

    async def test_deny_empty(self):
        backend = LocalApprovalBackend()
        req = await backend.request_approval("Tool", {}, "msg")

        with patch.object(backend, "_read_stdin", return_value=""):
            decision = await backend.wait_for_decision(req.approval_id)
        assert decision.approved is False
        assert decision.status == ApprovalStatus.DENIED


class TestAuditActionApprovalEvents:
    """The four HITL audit actions exist in AuditAction."""

    def test_approval_requested(self):
        assert AuditAction.CALL_APPROVAL_REQUESTED == "call_approval_requested"

    def test_approval_granted(self):
        assert AuditAction.CALL_APPROVAL_GRANTED == "call_approval_granted"

    def test_approval_denied(self):
        assert AuditAction.CALL_APPROVAL_DENIED == "call_approval_denied"

    def test_approval_timeout(self):
        assert AuditAction.CALL_APPROVAL_TIMEOUT == "call_approval_timeout"

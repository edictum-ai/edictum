"""Behavior tests for approval session lineage."""

from __future__ import annotations

import pytest

from edictum import Decision, Edictum, precondition
from edictum.approval import ApprovalDecision, ApprovalRequest, ApprovalStatus
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


class _CaptureApprovalBackend:
    def __init__(self) -> None:
        self.request: ApprovalRequest | None = None

    async def request_approval(
        self,
        tool_name: str,
        tool_args: dict,
        message: str,
        *,
        timeout: int = 300,
        timeout_action: str = "block",
        principal: dict | None = None,
        metadata: dict | None = None,
        session_id: str | None = None,
    ) -> ApprovalRequest:
        self.request = ApprovalRequest(
            approval_id="approval-1",
            tool_name=tool_name,
            tool_args=tool_args,
            message=message,
            timeout=timeout,
            timeout_action=timeout_action,
            principal=principal,
            metadata=metadata or {},
            session_id=session_id,
        )
        return self.request

    async def wait_for_decision(self, approval_id: str, timeout: int | None = None) -> ApprovalDecision:
        return ApprovalDecision(approved=True, status=ApprovalStatus.APPROVED, approver="tests")


def _approval_rule():
    @precondition("*")
    def requires_approval(tool_call):
        return Decision.fail("Approval required")

    requires_approval._edictum_effect = "ask"
    requires_approval._edictum_timeout = 60
    requires_approval._edictum_timeout_action = "block"
    return requires_approval


class TestApprovalSessionBehavior:
    @pytest.mark.asyncio
    async def test_run_forwards_session_id_to_approval_backend(self):
        backend = _CaptureApprovalBackend()
        guard = Edictum(
            rules=[_approval_rule()],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=backend,
        )

        await guard.run("TestTool", {}, lambda: "ok", session_id="workflow-session-123")

        assert backend.request is not None
        assert backend.request.session_id == "workflow-session-123"

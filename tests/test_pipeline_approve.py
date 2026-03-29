"""Tests for pipeline approval protocol and wildcard tool matching."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from edictum import (
    Decision,
    Edictum,
    EdictumDenied,
    precondition,
)
from edictum.approval import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    LocalApprovalBackend,
)
from edictum.envelope import create_envelope
from edictum.pipeline import CheckPipeline
from edictum.session import Session
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _make_approval_precondition(tool: str = "*"):
    """Create a precondition with action=ask."""

    @precondition(tool)
    def requires_approval(tool_call):
        return Decision.fail("Requires human approval")

    requires_approval._edictum_effect = "ask"
    requires_approval._edictum_timeout = 60
    requires_approval._edictum_timeout_action = "block"
    return requires_approval


class TestPreDecisionApproval:
    """Pre rule with action=ask returns pending_approval."""

    async def test_approve_effect_returns_pending_approval(self):
        backend = MemoryBackend()
        guard = Edictum(
            environment="test",
            rules=[_make_approval_precondition()],
            audit_sink=NullAuditSink(),
            backend=backend,
        )
        session = Session("test", backend)
        await session.increment_attempts()
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})

        decision = await pipeline.pre_execute(tool_call, session)

        assert decision.action == "pending_approval"
        assert decision.reason == "Requires human approval"

    async def test_approval_timeout_propagated(self):
        rule = _make_approval_precondition()
        rule._edictum_timeout = 120
        rule._edictum_timeout_action = "allow"

        backend = MemoryBackend()
        guard = Edictum(
            environment="test",
            rules=[rule],
            audit_sink=NullAuditSink(),
            backend=backend,
        )
        session = Session("test", backend)
        await session.increment_attempts()
        pipeline = CheckPipeline(guard)
        tool_call = create_envelope("TestTool", {})

        decision = await pipeline.pre_execute(tool_call, session)

        assert decision.action == "pending_approval"
        assert decision.approval_timeout == 120
        assert decision.approval_timeout_action == "allow"
        assert decision.approval_message == "Requires human approval"


@pytest.mark.security
class TestRunApprovalBackend:
    """run() approval backend integration."""

    async def test_no_backend_raises_denied(self):
        guard = Edictum(
            environment="test",
            rules=[_make_approval_precondition()],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )

        with pytest.raises(EdictumDenied, match="no approval backend configured"):
            await guard.run("TestTool", {}, lambda: "result")

    async def test_backend_approves_executes_tool(self):
        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="Requires human approval",
            timeout=60,
            timeout_action="block",
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=True,
            status=ApprovalStatus.APPROVED,
        )

        guard = Edictum(
            environment="test",
            rules=[_make_approval_precondition()],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=mock_backend,
        )

        result = await guard.run("TestTool", {}, lambda: "tool-result")

        assert result == "tool-result"
        mock_backend.request_approval.assert_awaited_once()
        mock_backend.wait_for_decision.assert_awaited_once()

    async def test_backend_denies_raises_denied(self):
        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="Requires human approval",
            timeout=60,
            timeout_action="block",
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=False,
            status=ApprovalStatus.DENIED,
            reason="Reviewer rejected",
        )

        guard = Edictum(
            environment="test",
            rules=[_make_approval_precondition()],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=mock_backend,
        )

        with pytest.raises(EdictumDenied, match="Reviewer rejected"):
            await guard.run("TestTool", {}, lambda: "result")

    async def test_backend_timeout_raises_denied(self):
        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="Requires human approval",
            timeout=60,
            timeout_action="block",
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=False,
            status=ApprovalStatus.TIMEOUT,
            reason="Approval timed out",
        )

        guard = Edictum(
            environment="test",
            rules=[_make_approval_precondition()],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=mock_backend,
        )

        with pytest.raises(EdictumDenied, match="Approval timed out"):
            await guard.run("TestTool", {}, lambda: "result")

    async def test_approval_emits_correct_audit_actions(self):
        """Approval flow emits CALL_APPROVAL_REQUESTED then CALL_APPROVAL_GRANTED."""
        from edictum.audit import AuditAction

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="Requires human approval",
            timeout=60,
            timeout_action="block",
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=True,
            status=ApprovalStatus.APPROVED,
        )

        sink = NullAuditSink()
        guard = Edictum(
            environment="test",
            rules=[_make_approval_precondition()],
            audit_sink=sink,
            backend=MemoryBackend(),
            approval_backend=mock_backend,
        )

        await guard.run("TestTool", {}, lambda: "result")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_APPROVAL_REQUESTED in actions
        assert AuditAction.CALL_APPROVAL_GRANTED in actions

    async def test_on_allow_fires_exactly_once_on_approval(self):
        """on_allow must fire exactly once when approval is granted (not twice)."""
        from unittest.mock import MagicMock

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="Requires human approval",
            timeout=60,
            timeout_action="block",
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=True,
            status=ApprovalStatus.APPROVED,
        )

        on_allow = MagicMock()
        guard = Edictum(
            environment="test",
            rules=[_make_approval_precondition()],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=mock_backend,
            on_allow=on_allow,
        )

        await guard.run("TestTool", {}, lambda: "result")
        assert on_allow.call_count == 1, f"on_allow fired {on_allow.call_count} times, expected 1"

    async def test_timeout_action_allow_executes_tool(self):
        """When timeout_action is 'allow', a timed-out approval should execute the tool."""
        rule = _make_approval_precondition()
        rule._edictum_timeout_action = "allow"

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="TestTool",
            tool_args={},
            message="Requires human approval",
            timeout=60,
            timeout_action="allow",
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=False,
            status=ApprovalStatus.TIMEOUT,
            reason="Approval timed out",
        )

        guard = Edictum(
            environment="test",
            rules=[rule],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=mock_backend,
        )

        result = await guard.run("TestTool", {}, lambda: "tool-result")
        assert result == "tool-result"

    async def test_local_approval_backend_via_run(self):
        """LocalApprovalBackend auto-approves via stdin mock."""
        from unittest.mock import patch

        backend = LocalApprovalBackend()
        guard = Edictum(
            environment="test",
            rules=[_make_approval_precondition()],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=backend,
        )

        with patch.object(backend, "_read_stdin", return_value="y"):
            result = await guard.run("TestTool", {}, lambda: "tool-result")

        assert result == "tool-result"
        assert len(backend._pending) == 1


class TestYamlApproveEffect:
    """YAML rule with action: ask compiles correctly."""

    def test_yaml_approve_compiles(self):
        yaml_content = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-ask
defaults:
  mode: enforce
rules:
  - id: require-approval
    type: pre
    tool: dangerous_tool
    when:
      args.action:
        equals: delete
    then:
      action: ask
      message: "Deletion requires approval"
      timeout: 120
      timeout_action: allow
"""
        guard = Edictum.from_yaml_string(yaml_content, audit_sink=NullAuditSink())

        tool_call = create_envelope("dangerous_tool", {"action": "delete"})
        preconditions = guard.get_preconditions(tool_call)
        assert len(preconditions) == 1

        fn = preconditions[0]
        assert fn._edictum_effect == "ask"
        assert fn._edictum_timeout == 120
        assert fn._edictum_timeout_action == "allow"


class TestWildcardToolMatching:
    """Wildcard glob patterns in tool selectors."""

    def test_glob_pattern_matches(self):
        @precondition("mcp_*")
        def deny_mcp(tool_call):
            return Decision.fail("MCP denied")

        guard = Edictum(
            environment="test",
            rules=[deny_mcp],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )

        tool_call = create_envelope("mcp_postgres_query", {})
        assert len(guard.get_preconditions(tool_call)) == 1

    def test_glob_pattern_no_match(self):
        @precondition("read_*")
        def deny_reads(tool_call):
            return Decision.fail("Read denied")

        guard = Edictum(
            environment="test",
            rules=[deny_reads],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )

        tool_call = create_envelope("write_file", {})
        assert len(guard.get_preconditions(tool_call)) == 0

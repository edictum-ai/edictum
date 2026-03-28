"""Behavior tests for the approval_backend parameter on Edictum.

Each test proves an observable action of the approval_backend parameter:
- When None (default), no approval backend is stored
- When provided, it's stored and accessible
- from_yaml(), from_yaml_string(), from_template() accept the parameter
- from_multiple() preserves the approval backend from the first guard
- Timeout audit labels are accurate (TIMEOUT, not GRANTED)
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from edictum import Edictum, EdictumDenied, Decision, precondition
from edictum.approval import (
    ApprovalBackend,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    LocalApprovalBackend,
)
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

MINIMAL_YAML = """\
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: test-bundle
defaults:
  mode: enforce
rules:
  - id: noop
    type: pre
    tool: "__noop__"
    when:
      tool_name:
        equals: "__never_matches__"
    then:
      action: block
      message: "noop"
"""


def _make_guard(**overrides):
    defaults = dict(audit_sink=NullAuditSink(), backend=MemoryBackend())
    defaults.update(overrides)
    return Edictum(**defaults)


class TestApprovalBackendDefault:
    """Without approval_backend, the guard has no approval backend."""

    def test_default_is_none(self):
        guard = _make_guard()
        assert guard._approval_backend is None


class TestApprovalBackendProvided:
    """When approval_backend is provided, it's stored on the guard."""

    def test_stored_on_guard(self):
        backend = LocalApprovalBackend()
        guard = _make_guard(approval_backend=backend)
        assert guard._approval_backend is backend
        assert isinstance(guard._approval_backend, ApprovalBackend)


class TestApprovalBackendFromYaml:
    """from_yaml_string() passes approval_backend through to the constructor."""

    def test_from_yaml_string_with_backend(self, tmp_path):
        backend = LocalApprovalBackend()
        guard = Edictum.from_yaml_string(
            MINIMAL_YAML,
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=backend,
        )
        assert guard._approval_backend is backend

    def test_from_yaml_string_without_backend(self):
        guard = Edictum.from_yaml_string(
            MINIMAL_YAML,
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )
        assert guard._approval_backend is None


class TestApprovalBackendFromYamlFile:
    """from_yaml() passes approval_backend through to the constructor."""

    def test_from_yaml_with_backend(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text(MINIMAL_YAML)

        backend = LocalApprovalBackend()
        guard = Edictum.from_yaml(
            yaml_file,
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=backend,
        )
        assert guard._approval_backend is backend


class TestApprovalBackendFromTemplate:
    """from_template() passes approval_backend through."""

    def test_from_template_with_backend(self):
        backend = LocalApprovalBackend()
        guard = Edictum.from_template(
            "file-agent",
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
            approval_backend=backend,
        )
        assert guard._approval_backend is backend


class TestApprovalBackendFromMultiple:
    """from_multiple() preserves approval_backend from the first guard."""

    def test_from_multiple_preserves_backend(self):
        backend = LocalApprovalBackend()
        guard1 = _make_guard(approval_backend=backend)
        guard2 = _make_guard()

        merged = Edictum.from_multiple([guard1, guard2])
        assert merged._approval_backend is backend

    def test_from_multiple_none_when_first_has_none(self):
        guard1 = _make_guard()
        guard2 = _make_guard(approval_backend=LocalApprovalBackend())

        merged = Edictum.from_multiple([guard1, guard2])
        assert merged._approval_backend is None


# ---------------------------------------------------------------------------
# Approval timeout audit accuracy tests
# ---------------------------------------------------------------------------


def _make_approval_contract(timeout_action: str = "block"):
    """Create a precondition with action=ask and given timeout_action."""

    @precondition("*")
    def requires_approval(tool_call):
        return Decision.fail("Requires human approval")

    requires_approval._edictum_effect = "ask"
    requires_approval._edictum_timeout = 60
    requires_approval._edictum_timeout_action = timeout_action
    return requires_approval


def _make_mock_approval_backend(decision: ApprovalDecision) -> ApprovalBackend:
    """Create a mock approval backend that returns a fixed decision."""
    backend = MagicMock(spec=ApprovalBackend)
    backend.request_approval = AsyncMock(
        return_value=ApprovalRequest(
            approval_id="test-id",
            tool_name="test-tool",
            tool_args={},
            message="Approve?",
            timeout=10,
        )
    )
    backend.wait_for_decision = AsyncMock(return_value=decision)
    return backend


@pytest.mark.security
class TestApprovalTimeoutAuditAccuracy:
    """Security: timeout emits TIMEOUT, not GRANTED, regardless of approved flag."""

    @pytest.mark.asyncio
    async def test_timeout_with_allow_emits_timeout_not_granted(self):
        """When timeout_action=allow and timeout occurs, audit says TIMEOUT not GRANTED."""
        sink = NullAuditSink()
        decision = ApprovalDecision(approved=True, status=ApprovalStatus.TIMEOUT)
        approval = _make_mock_approval_backend(decision)

        guard = Edictum(
            environment="test",
            rules=[_make_approval_contract(timeout_action="allow")],
            audit_sink=sink,
            backend=MemoryBackend(),
            approval_backend=approval,
        )

        await guard.run("TestTool", {}, lambda: "ok")

        audit_actions = [e.action for e in sink.events]
        assert AuditAction.CALL_APPROVAL_TIMEOUT in audit_actions
        assert AuditAction.CALL_APPROVAL_GRANTED not in audit_actions

    @pytest.mark.asyncio
    async def test_timeout_with_deny_emits_timeout(self):
        """When timeout_action=block and timeout occurs, audit says TIMEOUT and call is denied."""
        sink = NullAuditSink()
        decision = ApprovalDecision(approved=False, status=ApprovalStatus.TIMEOUT)
        approval = _make_mock_approval_backend(decision)

        guard = Edictum(
            environment="test",
            rules=[_make_approval_contract(timeout_action="block")],
            audit_sink=sink,
            backend=MemoryBackend(),
            approval_backend=approval,
        )

        with pytest.raises(EdictumDenied):
            await guard.run("TestTool", {}, lambda: "ok")

        audit_actions = [e.action for e in sink.events]
        assert AuditAction.CALL_APPROVAL_TIMEOUT in audit_actions

    @pytest.mark.asyncio
    async def test_explicit_approval_emits_granted(self):
        """Explicit human approval emits GRANTED (regression guard)."""
        sink = NullAuditSink()
        decision = ApprovalDecision(approved=True, status=ApprovalStatus.APPROVED, approver="human")
        approval = _make_mock_approval_backend(decision)

        guard = Edictum(
            environment="test",
            rules=[_make_approval_contract(timeout_action="allow")],
            audit_sink=sink,
            backend=MemoryBackend(),
            approval_backend=approval,
        )

        await guard.run("TestTool", {}, lambda: "ok")

        audit_actions = [e.action for e in sink.events]
        assert AuditAction.CALL_APPROVAL_GRANTED in audit_actions
        assert AuditAction.CALL_APPROVAL_TIMEOUT not in audit_actions

    @pytest.mark.asyncio
    async def test_explicit_denial_emits_denied(self):
        """Explicit human denial emits DENIED (regression guard)."""
        sink = NullAuditSink()
        decision = ApprovalDecision(approved=False, status=ApprovalStatus.DENIED, approver="human")
        approval = _make_mock_approval_backend(decision)

        guard = Edictum(
            environment="test",
            rules=[_make_approval_contract(timeout_action="block")],
            audit_sink=sink,
            backend=MemoryBackend(),
            approval_backend=approval,
        )

        with pytest.raises(EdictumDenied):
            await guard.run("TestTool", {}, lambda: "ok")

        audit_actions = [e.action for e in sink.events]
        assert AuditAction.CALL_APPROVAL_DENIED in audit_actions
        assert AuditAction.CALL_APPROVAL_TIMEOUT not in audit_actions

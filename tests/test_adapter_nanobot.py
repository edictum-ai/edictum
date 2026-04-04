"""Tests for NanobotAdapter and GovernedToolRegistry."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock

from edictum import Decision, Edictum, Principal, postcondition, precondition
from edictum.adapters.nanobot import GovernedToolRegistry, NanobotAdapter
from edictum.approval import ApprovalDecision, ApprovalRequest, ApprovalStatus
from edictum.audit import AuditAction
from edictum.envelope import create_envelope
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

# -- Mock nanobot types (no import from nanobot) --


class MockToolRegistry:
    def __init__(self):
        self._tools: dict[str, tuple] = {}

    def register(self, name: str, handler, description: str = "") -> None:
        self._tools[name] = (handler, description)

    async def execute(self, name: str, args: dict) -> str:
        handler, _ = self._tools[name]
        result = handler(**args)
        if asyncio.iscoroutine(result):
            result = await result
        return str(result)

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())

    def get_description(self, name: str) -> str:
        return self._tools[name][1]


@dataclass
class MockInboundMessage:
    content: str = ""
    sender_id: str = "user123"
    channel: str = "telegram"
    channel_id: str = "chat456"
    metadata: dict = field(default_factory=dict)


def make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


def make_registry():
    reg = MockToolRegistry()
    reg.register("read_file", lambda path: f"contents of {path}", "Read a file")
    reg.register("write_file", lambda path, content: f"wrote {path}", "Write a file")
    return reg


class TestGovernedToolRegistry:
    async def test_execute_allowed(self):
        guard = make_guard()
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="test")

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert result == "contents of /tmp/test.txt"

    async def test_execute_denied_enforce(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("not allowed")

        guard = make_guard(rules=[always_deny])
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert result.startswith("[DENIED]")
        assert "not allowed" in result

    async def test_execute_denied_observe(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would be blocked")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        # Should execute normally in observe mode
        assert result == "contents of /tmp/test.txt"
        # Should emit CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)

    async def test_execute_approval_flow(self):
        @precondition("*")
        def require_approval(tool_call):
            return Decision.fail("needs approval")

        require_approval._edictum_effect = "ask"
        require_approval._edictum_timeout = 60
        require_approval._edictum_timeout_action = "block"

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="read_file",
            tool_args={"path": "/tmp/test.txt"},
            message="needs approval",
            timeout=60,
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=True,
            approver="admin",
            status=ApprovalStatus.APPROVED,
        )

        guard = make_guard(rules=[require_approval], approval_backend=mock_backend)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="approval-session")

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert result == "contents of /tmp/test.txt"
        mock_backend.request_approval.assert_called_once()
        mock_backend.wait_for_decision.assert_called_once()
        assert mock_backend.request_approval.call_args.kwargs["session_id"] == "approval-session"

    async def test_execute_approval_flow_supports_legacy_backend_without_session_id(self):
        @precondition("*")
        def require_approval(tool_call):
            return Decision.fail("needs approval")

        require_approval._edictum_effect = "ask"
        require_approval._edictum_timeout = 60
        require_approval._edictum_timeout_action = "block"

        class LegacyApprovalBackend:
            def __init__(self):
                self.request: ApprovalRequest | None = None

            async def request_approval(
                self,
                tool_name: str,
                tool_args: dict[str, str],
                message: str,
                *,
                timeout: int = 300,
                timeout_action: str = "block",
                principal: dict | None = None,
                metadata: dict | None = None,
            ) -> ApprovalRequest:
                self.request = ApprovalRequest(
                    approval_id="req-legacy",
                    tool_name=tool_name,
                    tool_args=tool_args,
                    message=message,
                    timeout=timeout,
                    timeout_action=timeout_action,
                    principal=principal,
                    metadata=metadata or {},
                )
                return self.request

            async def wait_for_decision(self, approval_id: str, timeout: int | None = None) -> ApprovalDecision:
                return ApprovalDecision(
                    approved=True,
                    approver="legacy",
                    status=ApprovalStatus.APPROVED,
                )

        backend = LegacyApprovalBackend()
        guard = make_guard(rules=[require_approval], approval_backend=backend)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="approval-session")

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})

        assert result == "contents of /tmp/test.txt"
        assert backend.request is not None
        assert backend.request.session_id is None

    async def test_execute_approval_denied(self):
        @precondition("*")
        def require_approval(tool_call):
            return Decision.fail("needs approval")

        require_approval._edictum_effect = "ask"
        require_approval._edictum_timeout = 60
        require_approval._edictum_timeout_action = "block"

        mock_backend = AsyncMock()
        mock_backend.request_approval.return_value = ApprovalRequest(
            approval_id="req-1",
            tool_name="read_file",
            tool_args={},
            message="needs approval",
            timeout=60,
        )
        mock_backend.wait_for_decision.return_value = ApprovalDecision(
            approved=False,
            reason="rejected by reviewer",
            status=ApprovalStatus.DENIED,
        )

        guard = make_guard(rules=[require_approval], approval_backend=mock_backend)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert "[DENIED]" in result
        assert "Approval blocked" in result

    async def test_execute_no_approval_backend(self):
        @precondition("*")
        def require_approval(tool_call):
            return Decision.fail("needs approval")

        require_approval._edictum_effect = "ask"

        guard = make_guard(rules=[require_approval])
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert "[DENIED]" in result
        assert "no approval backend" in result.lower()

    async def test_delegates_register(self):
        guard = make_guard()
        inner = MockToolRegistry()
        governed = GovernedToolRegistry(inner, guard)

        governed.register("new_tool", lambda: "ok", "A new tool")
        assert "new_tool" in inner.list_tools()

    async def test_delegates_list_tools(self):
        guard = make_guard()
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        assert governed.list_tools() == inner.list_tools()

    async def test_delegates_get_description(self):
        guard = make_guard()
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        assert governed.get_description("read_file") == "Read a file"

    async def test_for_subagent(self):
        guard = make_guard()
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="parent", principal=Principal(role="admin"))

        child = governed.for_subagent(session_id="child-1")
        assert child.session_id == "child-1"
        assert child._principal == Principal(role="admin")
        assert child._inner is inner
        assert child._guard is guard

    async def test_for_subagent_default_session(self):
        guard = make_guard()
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="parent")

        child = governed.for_subagent()
        assert child.session_id != "parent"  # Gets its own session

    async def test_for_subagent_emits_parent_session_lineage(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="parent")

        child = governed.for_subagent(session_id="child-1")
        result = await child.execute("read_file", {"path": "/tmp/test.txt"})

        assert result == "contents of /tmp/test.txt"
        assert len(sink.events) >= 2
        assert {event.session_id for event in sink.events} == {"child-1"}
        assert {event.parent_session_id for event in sink.events} == {"parent"}

    async def test_invalid_parent_session_id_is_omitted_from_audit(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="child-1")
        governed._parent_session_id = "parent:invalid"

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})

        assert result == "contents of /tmp/test.txt"
        assert len(sink.events) >= 2
        assert {event.parent_session_id for event in sink.events} == {None}

    async def test_set_principal(self):
        @precondition("*")
        def require_admin(tool_call):
            if tool_call.principal is None or tool_call.principal.role != "admin":
                return Decision.fail("admin required")
            return Decision.pass_()

        guard = make_guard(rules=[require_admin])
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, principal=Principal(role="viewer"))

        # First call: viewer -> blocked
        result1 = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert "[DENIED]" in result1

        # Update principal
        governed.set_principal(Principal(role="admin"))

        # Second call: admin -> allowed
        result2 = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert result2 == "contents of /tmp/test.txt"

    async def test_postcondition_warnings(self):
        @postcondition("*")
        def detect_issue(tool_call, result):
            return Decision.fail("issue found in output")

        sink = NullAuditSink()
        guard = make_guard(rules=[detect_issue], audit_sink=sink)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        # Result is still returned (postcondition warnings don't block)
        assert "contents of /tmp/test.txt" in result

        # Verify postcondition was evaluated in audit
        exec_events = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert len(exec_events) == 1
        assert exec_events[0].postconditions_passed is False

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="nanobot-session")

        await governed.execute("read_file", {"path": "/tmp/test.txt"})

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions
        assert {event.session_id for event in sink.events} == {"nanobot-session"}

    async def test_workflow_state_updated_events_use_correct_audit_action(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="nanobot-session")
        envelope = create_envelope(
            tool_name="read_file",
            tool_input={"path": "/tmp/test.txt"},
            run_id="nanobot-session",
            call_index=0,
            tool_use_id="call-1",
            environment=guard.environment,
            registry=guard.tool_registry,
        )

        await governed._emit_workflow_events(
            envelope,
            [
                {
                    "action": AuditAction.WORKFLOW_STATE_UPDATED.value,
                    "workflow": {"name": "nanobot-workflow", "active_stage": "review"},
                }
            ],
        )

        assert sink.events[-1].action == AuditAction.WORKFLOW_STATE_UPDATED
        assert sink.events[-1].session_id == "nanobot-session"

    async def test_audit_events_on_block(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("blocked")

        sink = NullAuditSink()
        guard = make_guard(rules=[always_deny], audit_sink=sink)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        await governed.execute("read_file", {"path": "/tmp/test.txt"})

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_DENIED in actions

    async def test_on_block_callback(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("not allowed")

        on_block = MagicMock()
        guard = make_guard(rules=[always_deny], on_block=on_block)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert on_block.call_count == 1

    async def test_on_allow_callback(self):
        on_allow = MagicMock()
        guard = make_guard(on_allow=on_allow)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, session_id="test")

        await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert on_allow.call_count == 1

    async def test_custom_success_check(self):
        def always_fail(tool_name, result):
            return False

        sink = NullAuditSink()
        guard = make_guard(success_check=always_fail, audit_sink=sink)
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard)

        await governed.execute("read_file", {"path": "/tmp/test.txt"})

        failed = [e for e in sink.events if e.action == AuditAction.CALL_FAILED]
        assert len(failed) == 1

    async def test_principal_resolver(self):
        @precondition("*")
        def require_admin(tool_call):
            if tool_call.principal is None or tool_call.principal.role != "admin":
                return Decision.fail("admin required")
            return Decision.pass_()

        def resolver(tool_name, tool_input):
            return Principal(role="admin")

        guard = make_guard(rules=[require_admin])
        inner = make_registry()
        governed = GovernedToolRegistry(inner, guard, principal=Principal(role="viewer"), principal_resolver=resolver)

        result = await governed.execute("read_file", {"path": "/tmp/test.txt"})
        assert "[DENIED]" not in result


class TestNanobotAdapter:
    def test_wrap_registry(self):
        guard = make_guard()
        adapter = NanobotAdapter(
            guard,
            session_id="sess-1",
            principal=Principal(role="admin"),
        )
        inner = make_registry()

        governed = adapter.wrap_registry(inner)
        assert isinstance(governed, GovernedToolRegistry)
        assert governed._inner is inner
        assert governed.session_id == "sess-1"
        assert governed._principal == Principal(role="admin")

    def test_principal_from_message(self):
        msg = MockInboundMessage(
            content="hello",
            sender_id="user123",
            channel="telegram",
            channel_id="chat456",
        )

        principal = NanobotAdapter.principal_from_message(msg)
        assert principal.user_id == "telegram:user123"
        assert principal.role == "user"
        assert principal.claims["channel"] == "telegram"
        assert principal.claims["channel_id"] == "chat456"

    def test_principal_from_message_missing_channel_id(self):
        """Gracefully handle messages without channel_id."""

        class MinimalMessage:
            content = "hello"
            sender_id = "user1"
            channel = "discord"

        principal = NanobotAdapter.principal_from_message(MinimalMessage())
        assert principal.user_id == "discord:user1"
        assert principal.claims["channel_id"] == ""


class TestNanobotTemplate:
    def test_nanobot_template_loads(self):
        guard = Edictum.from_template("nanobot-agent")
        assert guard is not None

    def test_nanobot_template_has_expected_contracts(self):
        guard = Edictum.from_template("nanobot-agent")
        rule_ids = set()
        for c in guard._state.preconditions:
            cid = getattr(c, "_edictum_id", None)
            if cid:
                rule_ids.add(cid)
        for c in guard._state.session_contracts:
            cid = getattr(c, "_edictum_id", None)
            if cid:
                rule_ids.add(cid)

        expected = {
            "ask-exec",
            "ask-spawn",
            "ask-cron",
            "block-write-outside-workspace",
            "block-edit-outside-workspace",
            "block-sensitive-reads",
            "ask-mcp-tools",
            "session-limits",
        }
        assert expected.issubset(rule_ids), f"Missing rules: {expected - rule_ids}"

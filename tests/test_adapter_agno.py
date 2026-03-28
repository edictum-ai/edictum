"""Tests for AgnoAdapter."""

from __future__ import annotations

from edictum import Edictum, Decision, precondition
from edictum.adapters.agno import AgnoAdapter
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


class TestAgnoAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = AgnoAdapter(guard, session_id="test-session")

        async def my_tool(key="value"):
            return "tool_result"

        result = await adapter._hook_async("TestTool", my_tool, {"key": "value"})
        assert result == "tool_result"

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        guard = make_guard(rules=[always_deny])
        adapter = AgnoAdapter(guard)

        async def my_tool(**kwargs):
            return "should not run"

        result = await adapter._hook_async("TestTool", my_tool, {})
        assert isinstance(result, str)
        assert result.startswith("DENIED:")
        assert "denied" in result

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = AgnoAdapter(guard)

        # Pre creates pending
        await adapter._pre("TestTool", {}, "call-1")
        assert "call-1" in adapter._pending

        # Post clears pending
        await adapter._post("call-1", "ok")
        assert "call-1" not in adapter._pending

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("no")

        guard = make_guard(rules=[always_deny])
        adapter = AgnoAdapter(guard)

        await adapter._pre("TestTool", {}, "call-1")
        assert "call-1" not in adapter._pending

    async def test_post_without_pending_returns_empty(self):
        from edictum.findings import PostCallResult

        guard = make_guard()
        adapter = AgnoAdapter(guard)
        result = await adapter._post("unknown")
        assert isinstance(result, PostCallResult)
        assert result.postconditions_passed is True

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = AgnoAdapter(guard)

        await adapter._pre("T", {}, "call-1")
        await adapter._pre("T", {}, "call-2")
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would be denied")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)
        adapter = AgnoAdapter(guard)

        result = await adapter._pre("TestTool", {}, "call-1")
        # Should allow through (empty dict)
        assert result == {}
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert "call-1" in adapter._pending

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = AgnoAdapter(guard)

        await adapter._pre("T", {}, "call-1")
        await adapter._post("call-1", "ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = AgnoAdapter(guard)

        assert adapter._check_tool_success("TestTool", None) is True
        assert adapter._check_tool_success("TestTool", "ok") is True
        assert adapter._check_tool_success("TestTool", {"result": "good"}) is True
        assert adapter._check_tool_success("TestTool", {"is_error": True}) is False
        assert adapter._check_tool_success("TestTool", "Error: something failed") is False
        assert adapter._check_tool_success("TestTool", "fatal: not a git repo") is False

    async def test_public_api_returns_framework_native(self):
        guard = make_guard()
        adapter = AgnoAdapter(guard)
        hook = adapter.as_tool_hook()
        assert callable(hook)

    async def test_session_id_default(self):
        guard = make_guard()
        adapter = AgnoAdapter(guard)
        assert adapter.session_id  # should be a UUID string

    async def test_hook_async_full_lifecycle(self):
        """Test the full wrap-around lifecycle: pre -> execute -> post."""
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = AgnoAdapter(guard)

        call_count = 0

        def my_sync_tool(x=1):
            nonlocal call_count
            call_count += 1
            return f"result_{x}"

        result = await adapter._hook_async("TestTool", my_sync_tool, {"x": 42})
        assert result == "result_42"
        assert call_count == 1

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_hook_async_tool_failure(self):
        """Test that tool exceptions are captured and audit emits CALL_FAILED."""
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = AgnoAdapter(guard)

        def failing_tool():
            raise RuntimeError("boom")

        result = await adapter._hook_async("TestTool", failing_tool, {})
        assert "Error:" in result

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_FAILED in actions

    async def test_observe_mode_full_lifecycle(self):
        """Test observe mode allows denied calls through and emits CALL_WOULD_DENY + CALL_EXECUTED."""

        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would block")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)
        adapter = AgnoAdapter(guard)

        def my_tool():
            return "ok"

        result = await adapter._hook_async("TestTool", my_tool, {})
        assert result == "ok"

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_WOULD_DENY in actions
        assert AuditAction.CALL_EXECUTED in actions

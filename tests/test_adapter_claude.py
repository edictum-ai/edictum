"""Tests for ClaudeAgentSDKAdapter."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from edictum import Edictum, Decision, postcondition, precondition
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
from edictum.audit import AuditAction
from edictum.findings import Finding
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


class TestClaudeAgentSDKAdapter:
    async def test_allow_returns_empty_dict(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard, session_id="test-session")
        result = await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={"key": "value"},
            tool_use_id="tu-1",
        )
        assert result == {}

    async def test_deny_returns_sdk_format(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        guard = make_guard(rules=[always_deny])
        adapter = ClaudeAgentSDKAdapter(guard)
        result = await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "block"
        assert result["hookSpecificOutput"]["permissionDecisionReason"] == "denied"
        assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)

        # Pre-tool-use stores pending
        await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        assert "tu-1" in adapter._pending

        # Post-tool-use clears pending
        await adapter._post_tool_use(tool_use_id="tu-1", tool_response="ok")
        assert "tu-1" not in adapter._pending

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("no")

        guard = make_guard(rules=[always_deny])
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        assert "tu-1" not in adapter._pending

    async def test_post_without_pending_returns_empty(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        result = await adapter._post_tool_use(tool_use_id="unknown")
        assert result == {}

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use(tool_name="T", tool_input={}, tool_use_id="tu-1")
        await adapter._pre_tool_use(tool_name="T", tool_input={}, tool_use_id="tu-2")
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would be denied")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard)

        result = await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        # Should allow through (empty dict)
        assert result == {}
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert "tu-1" in adapter._pending

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)

        assert adapter._check_tool_success("TestTool", None) is True
        assert adapter._check_tool_success("TestTool", "ok") is True
        assert adapter._check_tool_success("TestTool", {"result": "good"}) is True
        assert adapter._check_tool_success("TestTool", {"is_error": True}) is False
        assert adapter._check_tool_success("TestTool", "Error: something failed") is False
        assert adapter._check_tool_success("TestTool", "fatal: not a git repo") is False

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use(tool_name="T", tool_input={}, tool_use_id="tu-1")
        await adapter._post_tool_use(tool_use_id="tu-1", tool_response="ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_post_tool_warnings_in_output(self):
        from edictum.rules import postcondition as postc

        @postc("TestTool")
        def bad_result(tool_call, result):
            return Decision.fail("Result was bad")

        guard = make_guard(rules=[bad_result])
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use(tool_name="TestTool", tool_input={}, tool_use_id="tu-1")
        result = await adapter._post_tool_use(tool_use_id="tu-1", tool_response="bad")

        assert "hookSpecificOutput" in result
        assert "additionalContext" in result["hookSpecificOutput"]

    async def test_session_id_default(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        assert adapter.session_id  # should be a UUID string

    async def test_to_hook_callables(self):
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_hook_callables()
        assert "pre_tool_use" in hooks
        assert "post_tool_use" in hooks


class TestEdictumRun:
    async def test_run_allows_and_returns(self):
        guard = make_guard()

        async def my_tool(key):
            return f"result: {key}"

        result = await guard.run("TestTool", {"key": "hello"}, my_tool)
        assert result == "result: hello"

    async def test_run_emits_full_audit_trail(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)

        async def my_tool(**kwargs):
            return "ok"

        await guard.run("TestTool", {}, my_tool)
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_run_deny_raises(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied by precondition")

        guard = make_guard(rules=[always_deny])

        async def my_tool(**kwargs):
            return "ok"

        from edictum import EdictumDenied

        with pytest.raises(EdictumDenied) as exc_info:
            await guard.run("TestTool", {}, my_tool)
        assert exc_info.value.reason == "denied by precondition"

    async def test_run_deny_emits_audit_no_execute(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        sink = NullAuditSink()
        guard = make_guard(rules=[always_deny], audit_sink=sink)

        async def my_tool(**kwargs):
            return "ok"

        from edictum import EdictumDenied

        with pytest.raises(EdictumDenied):
            await guard.run("TestTool", {}, my_tool)
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_DENIED in actions
        # Denied means no execution audit
        assert AuditAction.CALL_EXECUTED not in actions
        assert AuditAction.CALL_ALLOWED not in actions

    async def test_run_tool_error_emits_call_failed(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)

        async def failing_tool(**kwargs):
            raise RuntimeError("boom")

        from edictum import EdictumToolError

        with pytest.raises(EdictumToolError):
            await guard.run("TestTool", {}, failing_tool)
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_FAILED in actions

    async def test_run_observe_mode_full_trail(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would block")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)

        async def my_tool(**kwargs):
            return "ok"

        result = await guard.run("TestTool", {}, my_tool)
        assert result == "ok"
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_WOULD_DENY in actions
        assert AuditAction.CALL_EXECUTED in actions


class TestClaudeSDKPostconditionCallback:
    """Test on_postcondition_warn callback via to_hook_callables()."""

    async def test_to_hook_callables_accepts_postcondition_callback(self):
        """to_hook_callables() should accept on_postcondition_warn parameter."""
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        callback = MagicMock(return_value="redacted")
        hooks = adapter.to_hook_callables(on_postcondition_warn=callback)
        assert "pre_tool_use" in hooks
        assert "post_tool_use" in hooks

    async def test_postcondition_callback_optional(self):
        """to_hook_callables() should work without callback (backward compatible)."""
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_hook_callables()
        assert "pre_tool_use" in hooks
        assert "post_tool_use" in hooks

    async def test_postcondition_callback_invoked_on_warn(self):
        """Callback should be invoked when postconditions produce violations."""

        @postcondition("TestTool")
        def detect_pii(tool_call, result):
            return Decision.fail("PII detected in output")

        callback = MagicMock(return_value="redacted")
        guard = make_guard(rules=[detect_pii])
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_hook_callables(on_postcondition_warn=callback)

        await hooks["pre_tool_use"]("TestTool", {"key": "val"}, "tu-1")
        await hooks["post_tool_use"](tool_use_id="tu-1", tool_response="Patient SSN: 123-45-6789")

        callback.assert_called_once()
        # Verify callback args: (result, violations)
        call_args = callback.call_args[0]
        assert call_args[0] == "Patient SSN: 123-45-6789"
        violations = call_args[1]
        assert len(violations) >= 1
        assert isinstance(violations[0], Finding)
        assert "PII detected" in violations[0].message

    async def test_postcondition_callback_not_called_when_passing(self):
        """Callback should NOT be invoked when postconditions pass."""
        guard = make_guard()
        adapter = ClaudeAgentSDKAdapter(guard)
        callback = MagicMock(return_value="redacted")
        hooks = adapter.to_hook_callables(on_postcondition_warn=callback)

        await hooks["pre_tool_use"]("TestTool", {"key": "val"}, "tu-1")
        await hooks["post_tool_use"](tool_use_id="tu-1", tool_response="ok")

        callback.assert_not_called()

    async def test_postcondition_callback_exception_does_not_break(self):
        """Callback exception should be caught, not break the hook."""

        @postcondition("TestTool")
        def detect_issue(tool_call, result):
            return Decision.fail("issue found")

        def exploding_callback(result, violations):
            raise RuntimeError("callback exploded")

        guard = make_guard(rules=[detect_issue])
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_hook_callables(on_postcondition_warn=exploding_callback)

        await hooks["pre_tool_use"]("TestTool", {}, "tu-1")
        # Should not raise
        result = await hooks["post_tool_use"](tool_use_id="tu-1", tool_response="bad data")
        # Hook should still return (warnings may be present)
        assert isinstance(result, dict)

    async def test_postcondition_callback_receives_correct_findings(self):
        """Callback should receive Finding objects with correct attributes."""

        @postcondition("TestTool")
        def detect_secret(tool_call, result):
            return Decision.fail("API token exposed in output")

        received_findings = []

        def capture_callback(result, violations):
            received_findings.extend(violations)

        guard = make_guard(rules=[detect_secret])
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_hook_callables(on_postcondition_warn=capture_callback)

        await hooks["pre_tool_use"]("TestTool", {}, "tu-1")
        await hooks["post_tool_use"](tool_use_id="tu-1", tool_response="token=abc123")

        assert len(received_findings) == 1
        f = received_findings[0]
        assert isinstance(f, Finding)
        assert f.rule_id == "detect_secret"
        assert "API token" in f.message

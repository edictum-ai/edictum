"""Tests for ClaudeAgentSDKAdapter."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from edictum import Decision, Edictum, Principal, postcondition, precondition
from edictum.adapters.claude_agent_sdk import (
    _INPUT_REPLACEMENT_REASON,
    _INVALID_TOOL_INPUT_REASON,
    _INVALID_TOOL_NAME_REASON,
    _MISSING_TOOL_USE_ID_REASON,
    _NO_GOVERNED_SNAPSHOT_REASON,
    _PERMISSION_BOUNDARY_REASON,
    ADAPTER_INTERNAL_EXCEPTION_REASON,
    ADAPTER_POST_HOOK_EXCEPTION_REASON,
    ClaudeAgentSDKAdapter,
)
from edictum.audit import AuditAction, CompositeSink
from edictum.findings import Finding
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

# claude-agent-sdk 0.2.135 adds "defer" to stop a run with a resumable tool call.
CLAUDE_PRE_TOOL_USE_DECISIONS = frozenset({"allow", "deny", "ask", "defer"})


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

    @pytest.mark.security
    async def test_block_emits_supported_sdk_wire_value(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("blocked")

        guard = make_guard(rules=[always_deny])
        adapter = ClaudeAgentSDKAdapter(guard)
        result = await adapter._pre_tool_use(
            tool_name="TestTool",
            tool_input={},
            tool_use_id="tu-1",
        )
        emitted = result["hookSpecificOutput"]
        assert emitted["permissionDecision"] in CLAUDE_PRE_TOOL_USE_DECISIONS
        assert emitted["permissionDecision"] == "deny"
        assert emitted["permissionDecisionReason"] == "blocked"
        assert emitted["hookEventName"] == "PreToolUse"

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
            return Decision.fail("would be blocked")

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
            return Decision.fail("blocked by precondition")

        guard = make_guard(rules=[always_deny])

        async def my_tool(**kwargs):
            return "ok"

        from edictum import EdictumDenied

        with pytest.raises(EdictumDenied) as exc_info:
            await guard.run("TestTool", {}, my_tool)
        assert exc_info.value.reason == "blocked by precondition"

    async def test_run_deny_emits_audit_no_execute(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("blocked")

        sink = NullAuditSink()
        guard = make_guard(rules=[always_deny], audit_sink=sink)

        async def my_tool(**kwargs):
            return "ok"

        from edictum import EdictumDenied

        with pytest.raises(EdictumDenied):
            await guard.run("TestTool", {}, my_tool)
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_DENIED in actions
        # Blocked means no execution audit
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


def _sdk_pre(adapter):
    return adapter.to_sdk_hooks()["PreToolUse"][0].hooks[0]


def _pre_input(tool_name="canary", tool_input=None, tool_use_id="tu-1"):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {} if tool_input is None else tool_input,
        "tool_use_id": tool_use_id,
    }


_ASK_RULES = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: claude-ask
defaults:
  mode: enforce
tools:
  canary:
    side_effect: write
rules:
  - id: ask-canary
    type: pre
    tool: canary
    when:
      args.payload: {equals: ping}
    then:
      action: ask
      message: would ask a human
      timeout: 30
      timeout_action: block
"""


class SpyApprovalBackend:
    def __init__(self) -> None:
        self.requests: list[dict] = []

    async def request_approval(self, **kwargs):
        from edictum.approval import ApprovalRequest

        self.requests.append(kwargs)
        return ApprovalRequest(
            approval_id="spy-1",
            tool_name=kwargs.get("tool_name", ""),
            tool_args=kwargs.get("tool_args") or {},
            message=kwargs.get("message") or "",
            timeout=kwargs.get("timeout") or 30,
        )

    async def wait_for_decision(self, approval_id: str, timeout: int | None = None):
        from edictum.approval import ApprovalDecision, ApprovalStatus

        return ApprovalDecision(approved=False, reason="spy-block", status=ApprovalStatus.DENIED)


class TestClaudeSdkHostHooks:
    """Host hook protocol: matchers, no-match {}, no SDK ask, fail-closed replacement, D7."""

    async def test_to_sdk_hooks_matchers_have_hooks(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        hooks = adapter.to_sdk_hooks()
        assert "PreToolUse" in hooks
        assert hooks["PreToolUse"][0].hooks
        assert hooks["PostToolUse"][0].hooks

    async def test_no_match_emits_nothing(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        result = await _sdk_pre(adapter)(_pre_input(), "tu-1", {"signal": None})
        assert result == {}
        assert "permissionDecision" not in result
        assert "hookSpecificOutput" not in result

    @pytest.mark.security
    async def test_block_emits_host_deny_not_ask(self):
        @precondition("*")
        def always_block(tool_call):
            return Decision.fail("canary blocked")

        adapter = ClaudeAgentSDKAdapter(make_guard(rules=[always_block]))
        result = await _sdk_pre(adapter)(_pre_input(), "tu-1", {"signal": None})
        emitted = result["hookSpecificOutput"]
        assert emitted["permissionDecision"] == "deny"
        assert emitted["permissionDecision"] != "ask"
        assert "canary blocked" in emitted["permissionDecisionReason"]

    @pytest.mark.security
    async def test_ask_uses_approval_backend_never_emits_sdk_ask(self):
        spy = SpyApprovalBackend()
        sink = NullAuditSink()
        guard = Edictum.from_yaml_string(
            _ASK_RULES,
            backend=MemoryBackend(),
            audit_sink=sink,
            approval_backend=spy,
        )
        adapter = ClaudeAgentSDKAdapter(guard)
        result = await _sdk_pre(adapter)(
            _pre_input(tool_input={"payload": "ping"}),
            "tu-1",
            {"signal": None},
        )
        assert spy.requests, "ask must go through Edictum ApprovalBackend"
        emitted = result.get("hookSpecificOutput") or {}
        assert emitted.get("permissionDecision") != "ask"
        assert emitted.get("permissionDecision") == "deny"

    @pytest.mark.security
    async def test_pretooluse_rejects_input_replacement(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        pre = _sdk_pre(adapter)
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        second = await pre(_pre_input(tool_input={"payload": "pwn"}), "tu-1", {"signal": None})
        assert second["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "BLOCKED" in second["hookSpecificOutput"]["permissionDecisionReason"]

    @pytest.mark.security
    async def test_replacement_clears_pending_and_ends_span(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        pre = _sdk_pre(adapter)
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        assert "tu-1" in adapter._pending
        envelope, _old = adapter._pending["tu-1"]
        span = MagicMock()
        adapter._pending["tu-1"] = (envelope, span)
        second = await pre(_pre_input(tool_input={"payload": "pwn"}), "tu-1", {"signal": None})
        assert second["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert second["hookSpecificOutput"]["permissionDecisionReason"] == _INPUT_REPLACEMENT_REASON
        assert "tu-1" not in adapter._pending
        assert "tu-1" not in adapter._pending_decisions
        span.end.assert_called_once()

    @pytest.mark.security
    async def test_replacement_emits_adapter_audit(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        pre = _sdk_pre(adapter)
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        assert any(e.action == AuditAction.CALL_ALLOWED for e in sink.events)
        second = await pre(_pre_input(tool_input={"payload": "pwn"}), "tu-1", {"signal": None})
        assert second["hookSpecificOutput"]["permissionDecision"] == "deny"
        events = [e for e in sink.events if e.reason == _INPUT_REPLACEMENT_REASON]
        assert events, f"replacement block missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"
        assert events[0].decision_name == _INPUT_REPLACEMENT_REASON
        assert events[0].tool_name == "canary"

    @pytest.mark.security
    async def test_replacement_audit_preserves_pending_identity(self):
        """CALL_DENIED after a governed allow must keep the envelope identity."""
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(
            make_guard(audit_sink=sink),
            principal=Principal(user_id="alice"),
        )
        pre = _sdk_pre(adapter)
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        allowed = [e for e in sink.events if e.action == AuditAction.CALL_ALLOWED]
        assert allowed
        allowed_event = allowed[0]
        assert allowed_event.call_id
        second = await pre(_pre_input(tool_input={"payload": "pwn"}), "tu-1", {"signal": None})
        assert second["hookSpecificOutput"]["permissionDecision"] == "deny"
        blocked = [e for e in sink.events if e.reason == _INPUT_REPLACEMENT_REASON]
        assert blocked
        event = blocked[0]
        assert event.action == AuditAction.CALL_DENIED
        assert event.run_id == allowed_event.run_id
        assert event.call_id == allowed_event.call_id
        assert event.call_index == allowed_event.call_index
        assert event.tool_name == allowed_event.tool_name
        assert event.tool_args == allowed_event.tool_args
        assert event.principal == allowed_event.principal

    @pytest.mark.security
    async def test_pretooluse_rejects_mutation_during_pre(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        tool_input = {"payload": "ping"}
        original = adapter._pipeline.pre_execute

        async def mutate_then_pre(envelope, session):
            tool_input["payload"] = "pwn"
            return await original(envelope, session)

        adapter._pipeline.pre_execute = mutate_then_pre
        result = await _sdk_pre(adapter)(
            _pre_input(tool_input=tool_input),
            "tu-1",
            {"signal": None},
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "BLOCKED" in result["hookSpecificOutput"]["permissionDecisionReason"]

    @pytest.mark.security
    async def test_pretooluse_rejects_missing_tool_use_id(self):
        """ID-less PreToolUse must deny and leave no unrecoverable pending entry."""
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        result = await _sdk_pre(adapter)(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "canary",
                "tool_input": {"payload": "ping"},
            },
            None,
            {"signal": None},
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert result["hookSpecificOutput"]["permissionDecisionReason"] == _MISSING_TOOL_USE_ID_REASON
        assert adapter._pending == {}
        assert adapter._pending_decisions == {}
        events = [e for e in sink.events if e.reason == _MISSING_TOOL_USE_ID_REASON]
        assert events, f"missing-id block missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"
        assert events[0].decision_name == _MISSING_TOOL_USE_ID_REASON
        assert events[0].tool_name == "canary"
        post = adapter.to_sdk_hooks()["PostToolUse"][0].hooks[0]
        post_result = await post(
            {"hook_event_name": "PostToolUse", "tool_response": "ok"},
            None,
            {"signal": None},
        )
        assert post_result == {}
        assert adapter._pending == {}
        assert adapter._pending_decisions == {}
        assert not any(e.action == AuditAction.CALL_EXECUTED for e in sink.events)

    @pytest.mark.security
    async def test_malformed_tool_input_blocks(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        result = await _sdk_pre(adapter)(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "canary",
                "tool_input": ["not", "a", "dict"],
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"

    @pytest.mark.security
    async def test_malformed_tool_input_emits_adapter_audit(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        result = await _sdk_pre(adapter)(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "canary",
                "tool_input": ["not", "a", "dict"],
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        events = [e for e in sink.events if e.reason == _INVALID_TOOL_INPUT_REASON]
        assert events, f"malformed block missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"
        assert events[0].decision_name == _INVALID_TOOL_INPUT_REASON
        assert events[0].tool_name == "canary"

    @pytest.mark.security
    async def test_wrap_no_pending_allow_denies_and_audits(self):
        """Permission allow without a governed snapshot must deny and audit."""
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        called = {"n": 0}

        async def allow_cb(tool_name, tool_input, context):
            called["n"] += 1
            return {"behavior": "allow"}

        wrapped = adapter.wrap_can_use_tool(allow_cb)
        result = await wrapped(
            "canary",
            {"payload": "ping"},
            type("Ctx", (), {"tool_use_id": "tu-1"})(),
        )
        assert result.behavior == "deny"
        assert result.message == _NO_GOVERNED_SNAPSHOT_REASON
        assert called["n"] == 0
        events = [e for e in sink.events if e.reason == _NO_GOVERNED_SNAPSHOT_REASON]
        assert events, f"no-pending block missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"
        assert events[0].decision_name == _NO_GOVERNED_SNAPSHOT_REASON
        assert events[0].tool_name == "canary"

    @pytest.mark.security
    async def test_wrap_can_use_tool_blocks_replacement(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        await _sdk_pre(adapter)(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})

        async def allow_cb(tool_name, tool_input, context):
            return {"behavior": "allow"}

        wrapped = adapter.wrap_can_use_tool(allow_cb)
        result = await wrapped(
            "canary",
            {"payload": "pwn"},
            type("Ctx", (), {"tool_use_id": "tu-1"})(),
        )
        assert result.behavior == "deny"
        assert "BLOCKED" in result.message

    @pytest.mark.security
    async def test_wrap_can_use_tool_strips_updated_input(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        await _sdk_pre(adapter)(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})

        async def rewrite_cb(tool_name, tool_input, context):
            return {"behavior": "allow", "updated_input": {"payload": "pwn"}}

        wrapped = adapter.wrap_can_use_tool(rewrite_cb)
        result = await wrapped(
            "canary",
            {"payload": "ping"},
            type("Ctx", (), {"tool_use_id": "tu-1"})(),
        )
        assert result.behavior == "deny"
        assert "BLOCKED" in result.message

    @pytest.mark.security
    async def test_wrap_mutation_emits_adapter_audit(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        await _sdk_pre(adapter)(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert any(e.action == AuditAction.CALL_ALLOWED for e in sink.events)
        envelope, _old = adapter._pending["tu-1"]
        span = MagicMock()
        adapter._pending["tu-1"] = (envelope, span)

        async def rewrite_cb(tool_name, tool_input, context):
            return {"behavior": "allow", "updated_input": {"payload": "pwn"}}

        wrapped = adapter.wrap_can_use_tool(rewrite_cb)
        result = await wrapped(
            "canary",
            {"payload": "ping"},
            type("Ctx", (), {"tool_use_id": "tu-1"})(),
        )
        assert result.behavior == "deny"
        events = [e for e in sink.events if e.reason == _PERMISSION_BOUNDARY_REASON]
        assert events, f"wrap mutation missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"
        assert events[0].decision_name == _PERMISSION_BOUNDARY_REASON
        allowed = [e for e in sink.events if e.action == AuditAction.CALL_ALLOWED]
        assert allowed
        assert events[0].run_id == allowed[0].run_id
        assert events[0].call_id == allowed[0].call_id
        assert events[0].call_index == allowed[0].call_index
        assert events[0].principal == allowed[0].principal
        assert any(e.action == AuditAction.CALL_DENIED for e in sink.events)
        assert "tu-1" not in adapter._pending
        assert "tu-1" not in adapter._pending_decisions
        span.end.assert_called_once()

    @pytest.mark.security
    async def test_wrap_deny_clears_pending_and_ends_span(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        await _sdk_pre(adapter)(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert "tu-1" in adapter._pending
        envelope, _old = adapter._pending["tu-1"]
        span = MagicMock()
        adapter._pending["tu-1"] = (envelope, span)

        async def deny_cb(tool_name, tool_input, context):
            return {"behavior": "deny", "message": "nope"}

        wrapped = adapter.wrap_can_use_tool(deny_cb)
        result = await wrapped(
            "canary",
            {"payload": "ping"},
            type("Ctx", (), {"tool_use_id": "tu-1"})(),
        )
        assert result.behavior == "deny"
        assert result.message == "nope"
        assert "tu-1" not in adapter._pending
        assert "tu-1" not in adapter._pending_decisions
        span.end.assert_called_once()

    @pytest.mark.security
    async def test_wrap_deny_clears_matched_pending_when_context_lacks_id(self):
        """Name+input match must clear that pending key when tool_use_id is missing."""
        adapter = ClaudeAgentSDKAdapter(make_guard())
        await _sdk_pre(adapter)(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert "tu-1" in adapter._pending
        envelope, _old = adapter._pending["tu-1"]
        span = MagicMock()
        adapter._pending["tu-1"] = (envelope, span)

        async def deny_cb(tool_name, tool_input, context):
            return {"behavior": "deny", "message": "nope"}

        wrapped = adapter.wrap_can_use_tool(deny_cb)
        result = await wrapped("canary", {"payload": "ping"}, type("Ctx", (), {})())
        assert result.behavior == "deny"
        assert result.message == "nope"
        assert "tu-1" not in adapter._pending
        assert "tu-1" not in adapter._pending_decisions
        assert "" not in adapter._pending
        span.end.assert_called_once()

    @pytest.mark.security
    async def test_wrap_deny_clears_matched_pending_when_context_id_unknown(self):
        """Unknown nonempty tool_use_id must still clear the unique name+input match."""
        adapter = ClaudeAgentSDKAdapter(make_guard())
        await _sdk_pre(adapter)(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert "tu-1" in adapter._pending
        envelope, _old = adapter._pending["tu-1"]
        span = MagicMock()
        adapter._pending["tu-1"] = (envelope, span)

        async def deny_cb(tool_name, tool_input, context):
            return {"behavior": "deny", "message": "nope"}

        wrapped = adapter.wrap_can_use_tool(deny_cb)
        result = await wrapped(
            "canary",
            {"payload": "ping"},
            type("Ctx", (), {"tool_use_id": "unknown-id"})(),
        )
        assert result.behavior == "deny"
        assert result.message == "nope"
        assert "tu-1" not in adapter._pending
        assert "tu-1" not in adapter._pending_decisions
        assert "unknown-id" not in adapter._pending
        span.end.assert_called_once()

    @pytest.mark.security
    async def test_wrap_no_id_does_not_clear_wrong_of_two_identical_pending(self):
        """Ambiguous no-ID name+input match must not pick or clear the first pending."""
        adapter = ClaudeAgentSDKAdapter(make_guard())
        await _sdk_pre(adapter)(
            _pre_input(tool_input={"payload": "ping"}, tool_use_id="tu-1"),
            "tu-1",
            {"signal": None},
        )
        await _sdk_pre(adapter)(
            _pre_input(tool_input={"payload": "ping"}, tool_use_id="tu-2"),
            "tu-2",
            {"signal": None},
        )
        env1, _old1 = adapter._pending["tu-1"]
        env2, _old2 = adapter._pending["tu-2"]
        span1 = MagicMock()
        span2 = MagicMock()
        adapter._pending["tu-1"] = (env1, span1)
        adapter._pending["tu-2"] = (env2, span2)

        async def deny_cb(tool_name, tool_input, context):
            return {"behavior": "deny", "message": "nope"}

        wrapped = adapter.wrap_can_use_tool(deny_cb)
        result = await wrapped("canary", {"payload": "ping"}, type("Ctx", (), {})())
        assert result.behavior == "deny"
        assert "tu-1" in adapter._pending
        assert "tu-2" in adapter._pending
        assert "tu-1" in adapter._pending_decisions
        assert "tu-2" in adapter._pending_decisions
        span1.end.assert_not_called()
        span2.end.assert_not_called()

    @pytest.mark.security
    async def test_wrap_deny_rejects_control_characters_in_message(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        await _sdk_pre(adapter)(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})

        async def deny_cb(tool_name, tool_input, context):
            return {"behavior": "deny", "message": "nope\x00\ninjected"}

        wrapped = adapter.wrap_can_use_tool(deny_cb)
        result = await wrapped(
            "canary",
            {"payload": "ping"},
            type("Ctx", (), {"tool_use_id": "tu-1"})(),
        )
        assert result.behavior == "deny"
        assert result.message == _PERMISSION_BOUNDARY_REASON
        assert "\x00" not in result.message
        assert "\n" not in result.message
        reasons = [e.reason or "" for e in sink.events]
        assert all("\x00" not in r and "\n" not in r for r in reasons), f"control chars leaked into audit: {reasons}"
        assert any(e.reason == _PERMISSION_BOUNDARY_REASON for e in sink.events)

    @pytest.mark.security
    async def test_malformed_redispatch_clears_pending(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        pre = _sdk_pre(adapter)
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        assert "tu-1" in adapter._pending
        envelope, _old = adapter._pending["tu-1"]
        span = MagicMock()
        adapter._pending["tu-1"] = (envelope, span)
        second = await pre(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "canary",
                "tool_input": ["not", "a", "dict"],
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert second["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "tu-1" not in adapter._pending
        assert "tu-1" not in adapter._pending_decisions
        span.end.assert_called_once()
        events = [e for e in sink.events if e.reason == _INVALID_TOOL_INPUT_REASON]
        assert events, f"malformed redispatch missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"

    @pytest.mark.security
    async def test_enforce_exception_fails_closed(self):
        from edictum.adapters.claude_agent_sdk import ADAPTER_INTERNAL_EXCEPTION_REASON

        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))

        async def explode(*args, **kwargs):
            raise RuntimeError("backend outage")

        adapter._pre_tool_use = explode
        result = await _sdk_pre(adapter)(_pre_input(), "tu-1", {"signal": None})
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        events = [e for e in sink.events if e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON]
        assert events
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"
        assert events[0].policy_error is True
        assert adapter._internal_exception_count == 1

    @pytest.mark.security
    async def test_observe_exception_allows_loudly(self):
        from edictum.adapters.claude_agent_sdk import ADAPTER_INTERNAL_EXCEPTION_REASON

        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(mode="observe", audit_sink=sink))

        async def explode(*args, **kwargs):
            raise RuntimeError("backend outage")

        adapter._pre_tool_use = explode
        result = await _sdk_pre(adapter)(_pre_input(), "tu-1", {"signal": None})
        assert result == {}
        events = [e for e in sink.events if e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON]
        assert events
        assert events[0].action == AuditAction.CALL_WOULD_DENY
        assert events[0].decision_source == "adapter"
        assert events[0].policy_error is True
        assert adapter._internal_exception_count == 1

    @pytest.mark.security
    async def test_observe_recovery_isolated_per_tool_call(self):
        """Overlapping observe PreToolUse must not stash the other call's envelope."""
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(mode="observe", audit_sink=sink))
        pre = _sdk_pre(adapter)
        original = adapter._pipeline.pre_execute
        a_started = asyncio.Event()
        release_a = asyncio.Event()

        async def staggered(envelope, session):
            if envelope.tool_use_id == "tu-a":
                a_started.set()
                await release_a.wait()
                raise RuntimeError("a failed after b progressed")
            return await original(envelope, session)

        adapter._pipeline.pre_execute = staggered

        async def run_a():
            return await pre(
                _pre_input(tool_name="tool_a", tool_input={"x": 1}, tool_use_id="tu-a"),
                "tu-a",
                {"signal": None},
            )

        async def run_b():
            await a_started.wait()
            result = await pre(
                _pre_input(tool_name="tool_b", tool_input={"y": 2}, tool_use_id="tu-b"),
                "tu-b",
                {"signal": None},
            )
            release_a.set()
            return result

        result_a, result_b = await asyncio.gather(run_a(), run_b())
        assert result_a == {}
        assert result_b == {}
        assert "tu-a" in adapter._pending
        assert "tu-b" in adapter._pending
        envelope_a, _span_a = adapter._pending["tu-a"]
        envelope_b, _span_b = adapter._pending["tu-b"]
        assert envelope_a.tool_name == "tool_a"
        assert envelope_a.args == {"x": 1}
        assert envelope_b.tool_name == "tool_b"
        assert envelope_b.args == {"y": 2}

    @pytest.mark.security
    @pytest.mark.parametrize("tool_name", ["", "bad/name", "bad\\name", "bad\x00name"])
    async def test_invalid_tool_name_blocks_in_observe(self, tool_name):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(mode="observe", audit_sink=sink))
        result = await _sdk_pre(adapter)(
            _pre_input(tool_name=tool_name, tool_input={"payload": "ping"}),
            "tu-1",
            {"signal": None},
        )
        assert result != {}
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert result["hookSpecificOutput"]["permissionDecisionReason"] == _INVALID_TOOL_NAME_REASON
        events = [e for e in sink.events if e.reason == _INVALID_TOOL_NAME_REASON]
        assert events, f"invalid tool_name missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"
        assert events[0].decision_name == _INVALID_TOOL_NAME_REASON
        assert not any(e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON for e in sink.events)
        assert adapter._internal_exception_count == 0
        assert adapter._pending == {}
        assert adapter._pending_decisions == {}

    @pytest.mark.security
    async def test_post_hook_exception_still_audits_execution(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}

        async def boom(*_args, **_kwargs):
            raise RuntimeError("session down")

        adapter._session.record_execution = boom
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        fallback = [e for e in sink.events if e.reason == ADAPTER_POST_HOOK_EXCEPTION_REASON]
        assert fallback, f"post-hook exception missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert fallback[0].action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)
        assert fallback[0].decision_source == "adapter"
        assert fallback[0].decision_name == ADAPTER_POST_HOOK_EXCEPTION_REASON
        assert fallback[0].policy_error is True
        assert fallback[0].tool_name == "canary"
        assert adapter._pending == {}
        assert adapter._pending_decisions == {}
        executed = [e for e in sink.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)]
        assert len(executed) == 1

    @pytest.mark.security
    async def test_late_post_hook_exception_does_not_double_count_execution(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}

        async def boom(*_args, **_kwargs):
            raise RuntimeError("workflow events down")

        adapter._emit_workflow_events = boom
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        executed = [e for e in sink.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)]
        assert len(executed) == 1, (
            f"late post-hook failure double-counted; got {[(e.action, e.reason) for e in sink.events]}"
        )
        assert executed[0].action == AuditAction.CALL_EXECUTED
        assert executed[0].reason != ADAPTER_POST_HOOK_EXCEPTION_REASON
        assert not any(e.reason == ADAPTER_POST_HOOK_EXCEPTION_REASON for e in sink.events)
        assert adapter._pending == {}
        assert adapter._pending_decisions == {}

    @pytest.mark.security
    async def test_post_hook_exception_reuses_cached_tool_success(self):
        """Recovery must reuse the primary success_check result, not rerun it."""
        calls: list[object] = []

        def stateful_success_check(tool_name: str, tool_response: object) -> bool:
            calls.append((tool_name, tool_response))
            return len(calls) == 1

        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink, success_check=stateful_success_check))
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}

        async def boom(*_args, **_kwargs):
            raise RuntimeError("session down")

        adapter._session.record_execution = boom
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        assert len(calls) == 1
        fallback = [e for e in sink.events if e.reason == ADAPTER_POST_HOOK_EXCEPTION_REASON]
        assert fallback, f"post-hook exception missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert fallback[0].action == AuditAction.CALL_EXECUTED
        assert fallback[0].tool_success is True
        executed = [e for e in sink.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)]
        assert len(executed) == 1

    @pytest.mark.security
    async def test_execution_audit_fallback_when_sink_rejects_before_accept(self):
        """A configured sink that rejects the primary execution emit must still receive fallback."""

        class _RejectFirstExecution:
            def __init__(self):
                self.calls = 0
                self.events = []

            async def emit(self, event):
                if event.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED):
                    self.calls += 1
                    if self.calls == 1:
                        raise RuntimeError("execution sink rejected before accept")
                self.events.append(event)

        configured = _RejectFirstExecution()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=configured))
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        executed = [e for e in configured.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)]
        assert executed, (
            f"configured sink missed execution after reject; got {[(e.action, e.reason) for e in configured.events]}"
        )
        assert configured.calls >= 2
        assert executed[0].action == AuditAction.CALL_EXECUTED
        assert executed[0].reason == ADAPTER_POST_HOOK_EXCEPTION_REASON
        assert adapter._pending == {}
        assert adapter._pending_decisions == {}

    @pytest.mark.security
    async def test_composite_partial_failure_does_not_double_count_local(self):
        """Local sink already accepted primary execution; fallback must not replay it."""

        class _FailDownstream:
            def __init__(self):
                self.events = []
                self.calls = 0

            async def emit(self, event):
                if event.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED):
                    self.calls += 1
                    if self.calls == 1:
                        raise RuntimeError("downstream rejected after local accept")
                self.events.append(event)

        configured = _FailDownstream()
        guard = make_guard(audit_sink=configured)
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        local_executed = [
            e for e in guard.local_sink.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)
        ]
        assert len(local_executed) == 1, (
            f"local sink double-counted execution; got {[(e.action, e.reason) for e in guard.local_sink.events]}"
        )
        configured_executed = [
            e for e in configured.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)
        ]
        assert configured_executed, (
            f"configured sink missed fallback; got {[(e.action, e.reason) for e in configured.events]}"
        )
        assert configured.calls >= 2
        assert configured_executed[0].reason == ADAPTER_POST_HOOK_EXCEPTION_REASON

    @pytest.mark.security
    async def test_workflow_events_emitted_when_execution_audit_falls_back(self):
        """record_result already advanced state; fallback must still emit workflow audits."""
        from dataclasses import replace
        from types import SimpleNamespace

        from edictum.workflow.result import WorkflowState

        class _RejectFirstExecution:
            def __init__(self):
                self.events = []
                self.calls = 0

            async def emit(self, event):
                if event.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED):
                    self.calls += 1
                    if self.calls == 1:
                        raise RuntimeError("execution sink rejected before accept")
                self.events.append(event)

        class _FakeRuntime:
            definition = SimpleNamespace(metadata=SimpleNamespace(name="demo", version="1"))

            async def record_result(self, session, stage_id, envelope):
                return [
                    {
                        "action": AuditAction.WORKFLOW_STAGE_ADVANCED.value,
                        "workflow": {"name": "demo", "active_stage": "s1"},
                    }
                ]

            async def state(self, session):
                state = WorkflowState(session_id=session.session_id, active_stage="s1")
                state.ensure_defaults()
                return state

        configured = _RejectFirstExecution()
        guard = make_guard(audit_sink=configured)
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        guard._workflow_runtime = _FakeRuntime()
        decision = adapter._pending_decisions["tu-1"]
        adapter._pending_decisions["tu-1"] = replace(decision, workflow_involved=True, workflow_stage_id="s1")
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        workflow_events = [
            e
            for e in configured.events
            if e.action in (AuditAction.WORKFLOW_STAGE_ADVANCED, AuditAction.WORKFLOW_COMPLETED)
        ]
        assert workflow_events, (
            f"workflow transition missing after fallback; got {[(e.action, e.reason) for e in configured.events]}"
        )
        local_workflow = [
            e
            for e in guard.local_sink.events
            if e.action in (AuditAction.WORKFLOW_STAGE_ADVANCED, AuditAction.WORKFLOW_COMPLETED)
        ]
        assert len(local_workflow) == 1
        assert adapter._pending == {}
        assert adapter._pending_decisions == {}

    @pytest.mark.security
    async def test_fallback_does_not_replay_sinks_without_event_buffers(self):
        """File-like sinks have no events list; explicit acks must still skip replay."""

        class _FileLike:
            def __init__(self):
                self.writes = []

            async def emit(self, event):
                self.writes.append(event)

        class _FailSecond:
            def __init__(self):
                self.events = []
                self.calls = 0

            async def emit(self, event):
                if event.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED):
                    self.calls += 1
                    if self.calls == 1:
                        raise RuntimeError("downstream rejected")
                self.events.append(event)

        file_like = _FileLike()
        failing = _FailSecond()
        guard = make_guard(audit_sink=[file_like, failing])
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        file_executed = [
            e for e in file_like.writes if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)
        ]
        assert len(file_executed) == 1, (
            f"file-like sink replayed; got {[(e.action, e.reason) for e in file_like.writes]}"
        )
        assert failing.calls >= 2
        assert any(e.action == AuditAction.CALL_EXECUTED for e in failing.events)

    @pytest.mark.security
    async def test_workflow_fallback_retries_sink_that_rejected_transition(self):
        """Local acceptance of a workflow event must not skip retrying the rejecting sink."""
        from dataclasses import replace
        from types import SimpleNamespace

        from edictum.workflow.result import WorkflowState

        class _FailWorkflowOnce:
            def __init__(self):
                self.events = []
                self.wf_calls = 0

            async def emit(self, event):
                if event.action in (AuditAction.WORKFLOW_STAGE_ADVANCED, AuditAction.WORKFLOW_COMPLETED):
                    self.wf_calls += 1
                    if self.wf_calls == 1:
                        raise RuntimeError("workflow sink rejected")
                self.events.append(event)

        class _FakeRuntime:
            definition = SimpleNamespace(metadata=SimpleNamespace(name="demo", version="1"))

            async def record_result(self, session, stage_id, envelope):
                return [
                    {
                        "action": AuditAction.WORKFLOW_STAGE_ADVANCED.value,
                        "workflow": {"name": "demo", "active_stage": "s1"},
                    }
                ]

            async def state(self, session):
                state = WorkflowState(session_id=session.session_id, active_stage="s1")
                state.ensure_defaults()
                return state

        configured = _FailWorkflowOnce()
        guard = make_guard(audit_sink=configured)
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        guard._workflow_runtime = _FakeRuntime()
        decision = adapter._pending_decisions["tu-1"]
        adapter._pending_decisions["tu-1"] = replace(decision, workflow_involved=True, workflow_stage_id="s1")
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        configured_wf = [
            e
            for e in configured.events
            if e.action in (AuditAction.WORKFLOW_STAGE_ADVANCED, AuditAction.WORKFLOW_COMPLETED)
        ]
        assert configured_wf, (
            f"configured sink missed workflow retry; got {[(e.action, e.reason) for e in configured.events]}"
        )
        local_wf = [
            e
            for e in guard.local_sink.events
            if e.action in (AuditAction.WORKFLOW_STAGE_ADVANCED, AuditAction.WORKFLOW_COMPLETED)
        ]
        assert len(local_wf) == 1

    @pytest.mark.security
    async def test_to_sdk_hooks_binds_warning_callback_per_set(self):
        @postcondition("*")
        def ssn_check(tool_call, result):
            if "123-45-6789" in str(result):
                return Decision.fail("SSN leaked")
            return Decision.ok()

        seen: list[str] = []

        def cb_a(result, violations):
            seen.append("a")

        def cb_b(result, violations):
            seen.append("b")

        adapter = ClaudeAgentSDKAdapter(make_guard(rules=[ssn_check]))
        first_hooks = adapter.to_sdk_hooks(on_postcondition_warn=cb_a)
        adapter.to_sdk_hooks(on_postcondition_warn=cb_b)
        pre = first_hooks["PreToolUse"][0].hooks[0]
        post = first_hooks["PostToolUse"][0].hooks[0]
        await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "Patient SSN: 123-45-6789",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert seen == ["a"], f"first hook set must keep its callback; got {seen}"

    @pytest.mark.security
    async def test_sink_acks_cleared_after_successful_post(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        leftover = [key for keys in adapter._sink_ack.values() for key in keys if key[0]]
        assert leftover == [], f"sink acks leaked after completion: {leftover}"

    @pytest.mark.security
    async def test_pre_hook_block_clears_workflow_sink_acks(self):
        from edictum.pipeline import PreDecision

        adapter = ClaudeAgentSDKAdapter(make_guard())

        async def fake_pre(envelope, session):
            return PreDecision(
                action="block",
                reason="session limit exceeded",
                decision_source="limits",
                decision_name="max_calls",
                workflow_events=[
                    {
                        "action": AuditAction.WORKFLOW_STAGE_ADVANCED.value,
                        "workflow": {
                            "name": "demo",
                            "active_stage": "s1",
                            "stage_id": "s0",
                            "to_stage_id": "s1",
                        },
                    }
                ],
            )

        adapter._pipeline.pre_execute = fake_pre
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        result = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
        leftover = [key for keys in adapter._sink_ack.values() for key in keys]
        assert leftover == [], f"pre-hook block leaked sink acks: {leftover}"

    @pytest.mark.security
    async def test_fallback_failure_clears_recovery_state(self):
        from dataclasses import replace
        from types import SimpleNamespace

        from edictum.workflow.result import WorkflowState

        class _AlwaysRejectExec:
            def __init__(self):
                self.events = []

            async def emit(self, event):
                if event.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED):
                    raise RuntimeError("sustained sink outage")
                self.events.append(event)

        class _FakeRuntime:
            definition = SimpleNamespace(metadata=SimpleNamespace(name="demo", version="1"))

            async def record_result(self, session, stage_id, envelope):
                return [
                    {
                        "action": AuditAction.WORKFLOW_STAGE_ADVANCED.value,
                        "workflow": {"name": "demo", "active_stage": "s1", "stage_id": "s0", "to_stage_id": "s1"},
                    }
                ]

            async def state(self, session):
                state = WorkflowState(session_id=session.session_id, active_stage="s1")
                state.ensure_defaults()
                return state

        configured = _AlwaysRejectExec()
        guard = make_guard(audit_sink=configured)
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        guard._workflow_runtime = _FakeRuntime()
        decision = adapter._pending_decisions["tu-1"]
        adapter._pending_decisions["tu-1"] = replace(decision, workflow_involved=True, workflow_stage_id="s1")
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        leftover = [key for keys in adapter._sink_ack.values() for key in keys]
        assert leftover == [], f"fallback failure leaked sink acks: {leftover}"
        assert adapter._pending_workflow_events == {}, (
            f"fallback failure leaked pending workflow events: {adapter._pending_workflow_events}"
        )

    @pytest.mark.security
    async def test_early_post_hook_recovery_records_execution(self):
        def boom_check(tool_name, tool_response):
            raise RuntimeError("success_check failed")

        adapter = ClaudeAgentSDKAdapter(make_guard(success_check=boom_check))
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        before = await adapter._session.execution_count()
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        after = await adapter._session.execution_count()
        assert after == before + 1, f"early recovery skipped record_execution; {before} -> {after}"

    @pytest.mark.security
    async def test_workflow_execution_fallback_does_not_replay_local(self):
        from dataclasses import replace
        from types import SimpleNamespace

        from edictum.workflow.result import WorkflowState

        class _FailExecOnce:
            def __init__(self):
                self.events = []
                self.calls = 0

            async def emit(self, event):
                if event.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED):
                    self.calls += 1
                    if self.calls == 1:
                        raise RuntimeError("downstream rejected workflow execution")
                self.events.append(event)

        class _FakeRuntime:
            definition = SimpleNamespace(metadata=SimpleNamespace(name="demo", version="1"))

            async def record_result(self, session, stage_id, envelope):
                return [
                    {
                        "action": AuditAction.WORKFLOW_STAGE_ADVANCED.value,
                        "workflow": {"name": "demo", "active_stage": "s1", "stage_id": "s0", "to_stage_id": "s1"},
                    }
                ]

            async def state(self, session):
                state = WorkflowState(session_id=session.session_id, active_stage="s1")
                state.ensure_defaults()
                return state

        configured = _FailExecOnce()
        guard = make_guard(audit_sink=configured)
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        guard._workflow_runtime = _FakeRuntime()
        decision = adapter._pending_decisions["tu-1"]
        adapter._pending_decisions["tu-1"] = replace(decision, workflow_involved=True, workflow_stage_id="s1")
        await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        local_executed = [
            e for e in guard.local_sink.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)
        ]
        assert len(local_executed) == 1, (
            f"workflow execution fallback replayed local; got {[(e.action, e.reason) for e in guard.local_sink.events]}"
        )

    @pytest.mark.security
    async def test_workflow_events_stashed_when_state_lookup_raises(self):
        from dataclasses import replace
        from types import SimpleNamespace

        class _FakeRuntime:
            definition = SimpleNamespace(metadata=SimpleNamespace(name="demo", version="1"))

            async def record_result(self, session, stage_id, envelope):
                return [
                    {
                        "action": AuditAction.WORKFLOW_STAGE_ADVANCED.value,
                        "workflow": {"name": "demo", "active_stage": "s1", "stage_id": "s0", "to_stage_id": "s1"},
                    }
                ]

            async def state(self, session):
                raise RuntimeError("workflow state lookup failed")

        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        guard._workflow_runtime = _FakeRuntime()
        decision = adapter._pending_decisions["tu-1"]
        adapter._pending_decisions["tu-1"] = replace(decision, workflow_involved=True, workflow_stage_id="s1")
        await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        workflow_events = [
            e for e in sink.events if e.action in (AuditAction.WORKFLOW_STAGE_ADVANCED, AuditAction.WORKFLOW_COMPLETED)
        ]
        assert workflow_events, (
            "stashed workflow transition missing after state() raise; "
            f"got {[(e.action, e.reason) for e in sink.events]}"
        )
        assert adapter._pending_workflow_events == {}

    @pytest.mark.security
    async def test_to_hook_callables_clears_recovery_after_complete(self):
        adapter = ClaudeAgentSDKAdapter(make_guard())
        hooks = adapter.to_hook_callables()
        await hooks["pre_tool_use"]("canary", {"payload": "ping"}, "tu-1")
        assert "tu-1" in adapter._hook_recovery
        await hooks["post_tool_use"](tool_use_id="tu-1", tool_response="ok")
        assert adapter._hook_recovery == {}, f"raw hook recovery leaked: {adapter._hook_recovery}"

    @pytest.mark.security
    async def test_multiple_workflow_transitions_are_not_collapsed(self):
        from dataclasses import replace
        from types import SimpleNamespace

        from edictum.workflow.result import WorkflowState

        class _FakeRuntime:
            definition = SimpleNamespace(metadata=SimpleNamespace(name="demo", version="1"))

            async def record_result(self, session, stage_id, envelope):
                # hydrate_workflow_events copies the final snapshot onto every
                # event; only stage_id / to_stage_id distinguish transitions.
                snapshot = {"name": "demo", "active_stage": "s3", "completed_stages": ["s1", "s2"]}
                return [
                    {
                        "action": AuditAction.WORKFLOW_STAGE_ADVANCED.value,
                        "workflow": {**snapshot, "stage_id": "s1", "to_stage_id": "s2"},
                    },
                    {
                        "action": AuditAction.WORKFLOW_STAGE_ADVANCED.value,
                        "workflow": {**snapshot, "stage_id": "s2", "to_stage_id": "s3"},
                    },
                ]

            async def state(self, session):
                state = WorkflowState(session_id=session.session_id, active_stage="s3", completed_stages=["s1", "s2"])
                state.ensure_defaults()
                return state

        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        guard._workflow_runtime = _FakeRuntime()
        decision = adapter._pending_decisions["tu-1"]
        adapter._pending_decisions["tu-1"] = replace(decision, workflow_involved=True, workflow_stage_id="s1")
        await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        transitions = [
            ((e.workflow or {}).get("stage_id"), (e.workflow or {}).get("to_stage_id"))
            for e in sink.events
            if e.action == AuditAction.WORKFLOW_STAGE_ADVANCED
        ]
        assert transitions == [("s1", "s2"), ("s2", "s3")], f"collapsed workflow transitions; got {transitions}"

    @pytest.mark.security
    async def test_nested_composite_partial_failure_does_not_double_count_leaves(self):
        """Guard wraps a caller CompositeSink; fallback must skip already-acked leaves."""

        class _AcceptLeaf:
            def __init__(self):
                self.events = []

            async def emit(self, event):
                self.events.append(event)

        class _FailOnceLeaf:
            def __init__(self):
                self.events = []
                self.calls = 0

            async def emit(self, event):
                if event.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED):
                    self.calls += 1
                    if self.calls == 1:
                        raise RuntimeError("nested child rejected")
                self.events.append(event)

        accepting = _AcceptLeaf()
        failing = _FailOnceLeaf()
        guard = make_guard(audit_sink=CompositeSink([accepting, failing]))
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        result = await post(
            {
                "hook_event_name": "PostToolUse",
                "tool_response": "ok",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        local_executed = [
            e for e in guard.local_sink.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)
        ]
        assert len(local_executed) == 1, (
            f"local sink double-counted; got {[(e.action, e.reason) for e in guard.local_sink.events]}"
        )
        accepted = [e for e in accepting.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)]
        assert len(accepted) == 1, (
            f"nested accepting leaf replayed; got {[(e.action, e.reason) for e in accepting.events]}"
        )
        failed = [e for e in failing.events if e.action in (AuditAction.CALL_EXECUTED, AuditAction.CALL_FAILED)]
        assert failed, f"failing leaf missed fallback; got {[(e.action, e.reason) for e in failing.events]}"
        assert failing.calls >= 2

    @pytest.mark.security
    async def test_post_failure_hook_exception_still_audits(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(make_guard(audit_sink=sink))
        hooks = adapter.to_sdk_hooks()
        pre = hooks["PreToolUse"][0].hooks[0]
        fail = hooks["PostToolUseFailure"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}

        async def boom(*_args, **_kwargs):
            raise RuntimeError("session down")

        adapter._session.record_execution = boom
        result = await fail(
            {
                "hook_event_name": "PostToolUseFailure",
                "error": "host failed",
                "tool_use_id": "tu-1",
            },
            "tu-1",
            {"signal": None},
        )
        assert result == {}
        fallback = [e for e in sink.events if e.reason == ADAPTER_POST_HOOK_EXCEPTION_REASON]
        assert fallback, f"post-failure exception missing audit; got {[(e.action, e.reason) for e in sink.events]}"
        assert fallback[0].action == AuditAction.CALL_FAILED
        assert fallback[0].decision_source == "adapter"
        assert fallback[0].policy_error is True
        assert fallback[0].tool_success is False

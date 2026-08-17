"""Behavior coverage for ClaudeAgentSDKAdapter.to_sdk_hooks parameters.

Public path only: the warn callback is wired through to_sdk_hooks, not
to_hook_callables.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from edictum import Decision, Edictum, postcondition
from edictum.adapters.claude_agent_sdk import (
    _INPUT_REPLACEMENT_REASON,
    _INVALID_TOOL_NAME_REASON,
    ClaudeAgentSDKAdapter,
)
from edictum.audit import AuditAction
from edictum.findings import Finding
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


def _pre_input(tool_name="TestTool", tool_input=None, tool_use_id="tu-1"):
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {} if tool_input is None else tool_input,
        "tool_use_id": tool_use_id,
    }


def _post_input(tool_name="TestTool", tool_response="ok", tool_use_id="tu-1"):
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": tool_name,
        "tool_input": {},
        "tool_response": tool_response,
        "tool_use_id": tool_use_id,
    }


class TestToSdkHooksPostconditionWarn:
    """on_postcondition_warn must be observable through to_sdk_hooks."""

    async def test_warn_callback_invoked_through_to_sdk_hooks(self):
        @postcondition("TestTool")
        def detect_issue(tool_call, result):
            return Decision.fail("issue detected")

        callback = MagicMock()
        guard = _make_guard(rules=[detect_issue])
        adapter = ClaudeAgentSDKAdapter(guard)
        hooks = adapter.to_sdk_hooks(on_postcondition_warn=callback)
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]

        await pre(_pre_input(), "tu-1", {"signal": None})
        await post(_post_input(tool_response="bad output"), "tu-1", {"signal": None})

        callback.assert_called_once()
        result, findings = callback.call_args[0]
        assert result == "bad output"
        assert findings
        assert isinstance(findings[0], Finding)
        assert "issue detected" in findings[0].message

    async def test_warn_callback_not_invoked_when_postconditions_pass(self):
        callback = MagicMock()
        adapter = ClaudeAgentSDKAdapter(_make_guard())
        hooks = adapter.to_sdk_hooks(on_postcondition_warn=callback)
        pre = hooks["PreToolUse"][0].hooks[0]
        post = hooks["PostToolUse"][0].hooks[0]

        await pre(_pre_input(), "tu-1", {"signal": None})
        await post(_post_input(tool_response="ok"), "tu-1", {"signal": None})

        callback.assert_not_called()


class TestToSdkHooksSecurityBoundaries:
    """Bypass attempts against PreToolUse must stay blocked on the public path."""

    @pytest.mark.security
    async def test_pretooluse_rejects_input_replacement(self):
        adapter = ClaudeAgentSDKAdapter(_make_guard())
        pre = adapter.to_sdk_hooks()["PreToolUse"][0].hooks[0]
        first = await pre(_pre_input(tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        assert first == {}
        second = await pre(_pre_input(tool_input={"payload": "pwn"}), "tu-1", {"signal": None})
        emitted = second["hookSpecificOutput"]
        assert emitted["permissionDecision"] == "deny"
        assert emitted["permissionDecisionReason"] == _INPUT_REPLACEMENT_REASON

    @pytest.mark.security
    async def test_invalid_tool_name_blocks_in_observe(self):
        sink = NullAuditSink()
        adapter = ClaudeAgentSDKAdapter(_make_guard(mode="observe", audit_sink=sink))
        pre = adapter.to_sdk_hooks()["PreToolUse"][0].hooks[0]
        result = await pre(_pre_input(tool_name="", tool_input={"payload": "ping"}), "tu-1", {"signal": None})
        emitted = result["hookSpecificOutput"]
        assert emitted["permissionDecision"] == "deny"
        assert emitted["permissionDecisionReason"] == _INVALID_TOOL_NAME_REASON
        events = [e for e in sink.events if e.reason == _INVALID_TOOL_NAME_REASON]
        assert events
        assert events[0].action == AuditAction.CALL_DENIED
        assert events[0].decision_source == "adapter"

"""Behavior tests for GoogleADKAdapter."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Decision, Edictum, Principal, precondition
from edictum.adapters.google_adk import GoogleADKAdapter
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


class TestGoogleADKBehavior:
    async def test_deny_returns_dict_not_string(self):
        """ADK denial MUST be dict, not string."""
        result = GoogleADKAdapter._deny("test reason")
        assert isinstance(result, dict)
        assert "error" in result
        assert "DENIED: test reason" == result["error"]

    async def test_auto_principal_resolution(self):
        """With no principal set, auto-resolves from mock ToolContext."""
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)

        mock_context = SimpleNamespace(
            function_call_id="fc-1",
            user_id="user-42",
            agent_name="research_agent",
        )

        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="fc-1",
            tool_context=mock_context,
        )

        tool_call, _ = adapter._pending["fc-1"]
        assert tool_call.principal is not None
        assert tool_call.principal.user_id == "user-42"
        assert tool_call.principal.claims.get("adk_agent_name") == "research_agent"

    async def test_auto_principal_disabled_with_explicit(self):
        """Explicit principal blocks auto-resolution from ToolContext."""
        explicit = Principal(user_id="admin-1", role="admin")
        guard = make_guard()
        adapter = GoogleADKAdapter(guard, principal=explicit)

        mock_context = SimpleNamespace(
            function_call_id="fc-1",
            user_id="user-42",
            agent_name="research_agent",
        )

        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="fc-1",
            tool_context=mock_context,
        )

        tool_call, _ = adapter._pending["fc-1"]
        assert tool_call.principal.user_id == "admin-1"
        assert tool_call.principal.role == "admin"

    async def test_error_callback_audit_emission(self):
        """_emit_error_audit emits CALL_FAILED audit event."""
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert "call-1" in adapter._pending

        await adapter._emit_error_audit("call-1", RuntimeError("tool crashed"))

        failed = [e for e in sink.events if e.action == AuditAction.CALL_FAILED]
        assert len(failed) == 1
        assert failed[0].tool_name == "TestTool"

    async def test_error_callback_clears_pending(self):
        """_emit_error_audit cleans up pending state."""
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)

        await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")
        assert "call-1" in adapter._pending

        await adapter._emit_error_audit("call-1", RuntimeError("boom"))
        assert "call-1" not in adapter._pending


@pytest.mark.security
class TestGoogleADKSecurity:
    async def test_tool_name_null_byte_rejected(self):
        """Null bytes in tool name are rejected with ValueError."""
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        with pytest.raises(ValueError):
            await adapter._pre("evil\x00tool", {}, "call-1")

    async def test_tool_name_newline_rejected(self):
        """Newlines in tool name are rejected with ValueError."""
        guard = make_guard()
        adapter = GoogleADKAdapter(guard)
        with pytest.raises(ValueError):
            await adapter._pre("evil\ntool", {}, "call-1")

    async def test_denial_reason_not_leaked(self):
        """Denial dict contains reason but no internal stack traces."""
        result = GoogleADKAdapter._deny("access denied")
        assert "DENIED: access denied" in result["error"]
        assert "Traceback" not in result["error"]

    async def test_denial_with_exception_text_safe(self):
        """Even if reason contains exception-like text, format is safe."""

        @precondition("*")
        def deny_with_long_reason(tool_call):
            return Decision.fail("policy violation: unauthorized access")

        guard = make_guard(rules=[deny_with_long_reason])
        adapter = GoogleADKAdapter(guard)
        result = await adapter._pre("TestTool", {}, "call-1")

        assert isinstance(result, dict)
        assert "DENIED:" in result["error"]
        assert "Traceback" not in str(result)

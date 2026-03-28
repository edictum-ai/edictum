"""Tests for LangChainAdapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from edictum import Edictum, Decision, precondition
from edictum.adapters.langchain import LangChainAdapter
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


def _make_request(tool_name: str = "TestTool", tool_args: dict | None = None, tool_call_id: str = "tc-1") -> Any:
    """Create a mock LangChain ToolCallRequest."""
    request = MagicMock()
    request.tool_call = {
        "name": tool_name,
        "args": tool_args or {},
        "id": tool_call_id,
    }
    return request


@dataclass
class FakeToolMessage:
    """Minimal stand-in for langchain.messages.ToolMessage."""

    content: str = ""
    tool_call_id: str = ""


class TestLangChainAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard, session_id="test-session")
        result = await adapter._pre_tool_call(_make_request())
        # None means "allow through"
        assert result is None

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        guard = make_guard(rules=[always_deny])
        adapter = LangChainAdapter(guard)
        result = await adapter._pre_tool_call(_make_request())
        assert result is not None
        assert hasattr(result, "content")
        assert result.content.startswith("DENIED:")
        assert "denied" in result.content
        assert result.tool_call_id == "tc-1"

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        request = _make_request()

        # Pre creates pending
        await adapter._pre_tool_call(request)
        assert "tc-1" in adapter._pending

        # Post clears pending
        await adapter._post_tool_call(request, "ok")
        assert "tc-1" not in adapter._pending

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("no")

        guard = make_guard(rules=[always_deny])
        adapter = LangChainAdapter(guard)

        await adapter._pre_tool_call(_make_request())
        assert "tc-1" not in adapter._pending

    async def test_post_without_pending_returns_postcallresult(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        request = _make_request(tool_call_id="unknown")
        # Should return a PostCallResult with passed=True
        from edictum.findings import PostCallResult

        result = await adapter._post_tool_call(request, "ok")
        assert isinstance(result, PostCallResult)
        assert result.postconditions_passed is True
        assert result.result == "ok"

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)

        await adapter._pre_tool_call(_make_request(tool_call_id="tc-1"))
        await adapter._pre_tool_call(_make_request(tool_call_id="tc-2"))
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would be denied")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)
        adapter = LangChainAdapter(guard)

        result = await adapter._pre_tool_call(_make_request())
        # Should allow through (None)
        assert result is None
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert "tc-1" in adapter._pending

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = LangChainAdapter(guard)
        request = _make_request()

        await adapter._pre_tool_call(request)
        await adapter._post_tool_call(request, "ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)

        assert adapter._check_tool_success("TestTool", None) is True
        assert adapter._check_tool_success("TestTool", "ok") is True
        assert adapter._check_tool_success("TestTool", {"result": "good"}) is True
        assert adapter._check_tool_success("TestTool", {"is_error": True}) is False
        assert adapter._check_tool_success("TestTool", "Error: something failed") is False
        assert adapter._check_tool_success("TestTool", "fatal: not a git repo") is False

        # LangChain ToolMessage-style result
        ok_msg = FakeToolMessage(content="success", tool_call_id="tc-1")
        assert adapter._check_tool_success("TestTool", ok_msg) is True

        err_msg = FakeToolMessage(content="Error: bad request", tool_call_id="tc-1")
        assert adapter._check_tool_success("TestTool", err_msg) is False

    async def test_public_api_returns_framework_native(self):
        """as_middleware() imports from langchain — test the adapter's internal methods instead."""
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        # Verify the adapter has the expected public method
        assert hasattr(adapter, "as_middleware")
        assert callable(adapter.as_middleware)

    async def test_session_id_default(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        assert adapter.session_id  # should be a UUID string

    async def test_deny_audit_event_emitted(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        sink = NullAuditSink()
        guard = make_guard(rules=[always_deny], audit_sink=sink)
        adapter = LangChainAdapter(guard)

        await adapter._pre_tool_call(_make_request())
        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_DENIED in actions

    async def test_failed_tool_emits_call_failed(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = LangChainAdapter(guard)
        request = _make_request()

        await adapter._pre_tool_call(request)
        err_result = FakeToolMessage(content="Error: boom", tool_call_id="tc-1")
        await adapter._post_tool_call(request, err_result)

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_FAILED in actions

    # ── as_tool_wrapper tests ─────────────────────────────────────────

    def test_as_tool_wrapper_returns_callable(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_tool_wrapper()
        assert callable(wrapper)

    async def test_tool_wrapper_allows_and_calls_handler(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_tool_wrapper()
        request = _make_request()

        handler_called = False

        def handler(req):
            nonlocal handler_called
            handler_called = True
            return FakeToolMessage(content="ok", tool_call_id="tc-1")

        result = wrapper(request, handler)
        assert handler_called
        assert result.content == "ok"

    async def test_tool_wrapper_denies_without_calling_handler(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        guard = make_guard(rules=[always_deny])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_tool_wrapper()
        request = _make_request()

        handler_called = False

        def handler(req):
            nonlocal handler_called
            handler_called = True
            return FakeToolMessage(content="ok", tool_call_id="tc-1")

        result = wrapper(request, handler)
        assert not handler_called
        assert "DENIED" in result.content

    async def test_tool_wrapper_emits_audit_events(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_tool_wrapper()
        request = _make_request()

        def handler(req):
            return FakeToolMessage(content="ok", tool_call_id="tc-1")

        wrapper(request, handler)

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    # ── as_async_tool_wrapper tests ───────────────────────────────────

    def test_as_async_tool_wrapper_returns_callable(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper()
        assert callable(wrapper)

    async def test_async_tool_wrapper_allows_and_calls_handler(self):
        guard = make_guard()
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper()
        request = _make_request()

        handler_called = False

        async def handler(req):
            nonlocal handler_called
            handler_called = True
            return FakeToolMessage(content="ok", tool_call_id="tc-1")

        result = await wrapper(request, handler)
        assert handler_called
        assert result.content == "ok"

    async def test_async_tool_wrapper_denies_without_calling_handler(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        guard = make_guard(rules=[always_deny])
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper()
        request = _make_request()

        handler_called = False

        async def handler(req):
            nonlocal handler_called
            handler_called = True
            return FakeToolMessage(content="ok", tool_call_id="tc-1")

        result = await wrapper(request, handler)
        assert not handler_called
        assert "DENIED" in result.content

    async def test_async_tool_wrapper_emits_audit_events(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = LangChainAdapter(guard)
        wrapper = adapter.as_async_tool_wrapper()
        request = _make_request()

        async def handler(req):
            return FakeToolMessage(content="ok", tool_call_id="tc-1")

        await wrapper(request, handler)

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

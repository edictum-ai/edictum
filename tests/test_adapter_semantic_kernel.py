"""Tests for SemanticKernelAdapter."""

from __future__ import annotations

from edictum import Edictum, Decision, postcondition, precondition
from edictum.adapters.semantic_kernel import SemanticKernelAdapter
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


class TestSemanticKernelAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard, session_id="test-session")
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={"key": "value"},
            call_id="call-1",
        )
        assert result == {}

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        guard = make_guard(rules=[always_deny])
        adapter = SemanticKernelAdapter(guard)
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert isinstance(result, str)
        assert "DENIED" in result
        assert "denied" in result

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)

        # Pre creates pending
        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert "call-1" in adapter._pending

        # Post clears pending
        await adapter._post(call_id="call-1", tool_response="ok")
        assert "call-1" not in adapter._pending

    async def test_deny_clears_pending(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("no")

        guard = make_guard(rules=[always_deny])
        adapter = SemanticKernelAdapter(guard)

        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert "call-1" not in adapter._pending

    async def test_post_without_pending_returns_empty(self):
        from edictum.findings import PostCallResult

        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)
        result = await adapter._post(call_id="unknown")
        assert isinstance(result, PostCallResult)
        assert result.postconditions_passed is True

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._pre(tool_name="T", tool_input={}, call_id="call-2")
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would be denied")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)
        adapter = SemanticKernelAdapter(guard)

        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        # Should allow through (empty dict)
        assert result == {}
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert "call-1" in adapter._pending

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = SemanticKernelAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._post(call_id="call-1", tool_response="ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)

        assert adapter._check_tool_success("TestTool", None) is True
        assert adapter._check_tool_success("TestTool", "ok") is True
        assert adapter._check_tool_success("TestTool", {"result": "good"}) is True
        assert adapter._check_tool_success("TestTool", {"is_error": True}) is False
        assert adapter._check_tool_success("TestTool", "Error: something failed") is False
        assert adapter._check_tool_success("TestTool", "fatal: not a git repo") is False

    async def test_public_api_returns_framework_native(self):
        guard = make_guard()
        adapter = SemanticKernelAdapter(guard)
        assert hasattr(adapter, "register")
        assert callable(adapter.register)


class TestSemanticKernelFunctionResultWrapping:
    """Regression tests for FunctionResult wrapping fix (v0.5.2).

    SK 1.39+ validates context.function_result as FunctionResult | None
    via pydantic. The adapter must wrap raw strings in FunctionResult.
    """

    async def test_deny_returns_string_for_wrapping(self):
        """Denial from _pre should return a string that register() wraps in FunctionResult."""

        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("access denied")

        guard = make_guard(rules=[always_deny])
        adapter = SemanticKernelAdapter(guard)
        result = await adapter._pre(tool_name="TestTool", tool_input={}, call_id="call-1")

        # _pre returns a string on denial — register() wraps it via _wrap_result()
        assert isinstance(result, str)
        assert "DENIED" in result
        assert "access denied" in result

    async def test_register_wraps_denial_in_function_result(self):
        """register() filter should wrap denial in FunctionResult, not raw string."""
        import sys
        from types import ModuleType, SimpleNamespace
        from unittest.mock import AsyncMock

        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("access denied")

        # Mock SK modules
        mock_sk_filters = ModuleType("semantic_kernel.filters")
        mock_sk_functions = ModuleType("semantic_kernel.functions")

        class MockFunctionResult:
            def __init__(self, function, value):
                self.function = function
                self.value = value

        class MockFilterTypes:
            AUTO_FUNCTION_INVOCATION = "auto_function_invocation"

        mock_sk_filters.FilterTypes = MockFilterTypes
        mock_sk_functions.FunctionResult = MockFunctionResult

        orig_filters = sys.modules.get("semantic_kernel.filters")
        orig_functions = sys.modules.get("semantic_kernel.functions")
        sys.modules["semantic_kernel.filters"] = mock_sk_filters
        sys.modules["semantic_kernel.functions"] = mock_sk_functions

        try:
            guard = make_guard(rules=[always_deny])
            adapter = SemanticKernelAdapter(guard)

            # Mock kernel with filter decorator
            captured_filter = None

            class MockKernel:
                def filter(self, filter_type):
                    def decorator(fn):
                        nonlocal captured_filter
                        captured_filter = fn
                        return fn

                    return decorator

            kernel = MockKernel()
            adapter.register(kernel)

            assert captured_filter is not None

            # Create mock context
            mock_metadata = SimpleNamespace(name="TestTool")
            context = SimpleNamespace(
                function=SimpleNamespace(name="TestTool", metadata=mock_metadata),
                arguments={"key": "value"},
                function_result=None,
                terminate=False,
            )

            await captured_filter(context, AsyncMock())

            # function_result should be FunctionResult, not raw string
            assert isinstance(context.function_result, MockFunctionResult)
            assert "DENIED" in str(context.function_result.value)
            assert context.terminate is True
        finally:
            if orig_filters is not None:
                sys.modules["semantic_kernel.filters"] = orig_filters
            else:
                sys.modules.pop("semantic_kernel.filters", None)
            if orig_functions is not None:
                sys.modules["semantic_kernel.functions"] = orig_functions
            else:
                sys.modules.pop("semantic_kernel.functions", None)

    async def test_register_wraps_postcondition_remediation_in_function_result(self):
        """Postcondition remediation should wrap callback result in FunctionResult.

        Uses a real postcondition rule that always warns, forcing the
        on_postcondition_warn callback path in the SK filter. Verifies the
        callback return value is wrapped in FunctionResult via _wrap_result().
        """
        import sys
        from types import ModuleType, SimpleNamespace

        @postcondition("*")
        def always_warn(tool_call, tool_response):
            return Decision.fail("PII detected in output")

        # Mock SK modules
        mock_sk_filters = ModuleType("semantic_kernel.filters")
        mock_sk_functions = ModuleType("semantic_kernel.functions")

        class MockFunctionResult:
            def __init__(self, function, value):
                self.function = function
                self.value = value

        class MockFilterTypes:
            AUTO_FUNCTION_INVOCATION = "auto_function_invocation"

        mock_sk_filters.FilterTypes = MockFilterTypes
        mock_sk_functions.FunctionResult = MockFunctionResult

        orig_filters = sys.modules.get("semantic_kernel.filters")
        orig_functions = sys.modules.get("semantic_kernel.functions")
        sys.modules["semantic_kernel.filters"] = mock_sk_filters
        sys.modules["semantic_kernel.functions"] = mock_sk_functions

        try:
            guard = make_guard(rules=[always_warn])
            adapter = SemanticKernelAdapter(guard)

            captured_filter = None

            class MockKernel:
                def filter(self, filter_type):
                    def decorator(fn):
                        nonlocal captured_filter
                        captured_filter = fn
                        return fn

                    return decorator

            def redact_callback(result, violations):
                return "[REDACTED]"

            kernel = MockKernel()
            adapter.register(kernel, on_postcondition_warn=redact_callback)

            assert captured_filter is not None

            # Create mock context — next() simulates tool execution
            mock_metadata = SimpleNamespace(name="TestTool")

            context = SimpleNamespace(
                function=SimpleNamespace(name="TestTool", metadata=mock_metadata),
                arguments={"key": "value"},
                function_result="raw output with SSN 123-45-6789",
                terminate=False,
            )

            # next() simulates the tool executing successfully
            async def mock_next(ctx):
                pass

            await captured_filter(context, mock_next)

            # Postcondition should have failed, callback should have been invoked,
            # and the result should be wrapped in FunctionResult
            assert isinstance(context.function_result, MockFunctionResult)
            assert context.function_result.value == "[REDACTED]"
        finally:
            if orig_filters is not None:
                sys.modules["semantic_kernel.filters"] = orig_filters
            else:
                sys.modules.pop("semantic_kernel.filters", None)
            if orig_functions is not None:
                sys.modules["semantic_kernel.functions"] = orig_functions
            else:
                sys.modules.pop("semantic_kernel.functions", None)

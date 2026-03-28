"""Behavior tests for SemanticKernelAdapter.terminate_on_deny parameter."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock

from edictum import Edictum, Decision, precondition
from edictum.adapters.semantic_kernel import SemanticKernelAdapter
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


def _install_sk_mocks():
    """Install mock SK modules and return (MockFunctionResult, cleanup_fn)."""
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

    def cleanup():
        if orig_filters is not None:
            sys.modules["semantic_kernel.filters"] = orig_filters
        else:
            sys.modules.pop("semantic_kernel.filters", None)
        if orig_functions is not None:
            sys.modules["semantic_kernel.functions"] = orig_functions
        else:
            sys.modules.pop("semantic_kernel.functions", None)

    return MockFunctionResult, cleanup


def _make_kernel_and_capture():
    """Create a mock kernel that captures the registered filter."""
    captured = {}

    class MockKernel:
        def filter(self, filter_type):
            def decorator(fn):
                captured["filter"] = fn
                return fn

            return decorator

    return MockKernel(), captured


def _make_context(tool_name="TestTool"):
    mock_metadata = SimpleNamespace(name=tool_name)
    return SimpleNamespace(
        function=SimpleNamespace(name=tool_name, metadata=mock_metadata),
        arguments={"key": "value"},
        function_result=None,
        terminate=False,
    )


class TestTerminateOnDeny:
    """terminate_on_deny controls whether a denial stops the kernel's remaining tool calls."""

    async def test_terminate_on_deny_true_by_default(self):
        """Default behavior: denial sets context.terminate = True."""
        _, cleanup = _install_sk_mocks()
        try:

            @precondition("*")
            def always_deny(tool_call):
                return Decision.fail("not allowed")

            guard = _make_guard(rules=[always_deny])
            adapter = SemanticKernelAdapter(guard)
            kernel, captured = _make_kernel_and_capture()
            adapter.register(kernel)

            context = _make_context()
            await captured["filter"](context, AsyncMock())

            assert context.terminate is True
        finally:
            cleanup()

    async def test_terminate_on_deny_false_does_not_terminate(self):
        """With terminate_on_deny=False, denial does NOT set context.terminate = True."""
        _, cleanup = _install_sk_mocks()
        try:

            @precondition("*")
            def always_deny(tool_call):
                return Decision.fail("not allowed")

            guard = _make_guard(rules=[always_deny])
            adapter = SemanticKernelAdapter(guard, terminate_on_deny=False)
            kernel, captured = _make_kernel_and_capture()
            adapter.register(kernel)

            context = _make_context()
            await captured["filter"](context, AsyncMock())

            assert context.terminate is False
        finally:
            cleanup()

    async def test_terminate_on_deny_false_still_denies(self):
        """With terminate_on_deny=False, the tool is still denied (result set, next not called)."""
        mock_fr_cls, cleanup = _install_sk_mocks()
        try:

            @precondition("*")
            def always_deny(tool_call):
                return Decision.fail("not allowed")

            guard = _make_guard(rules=[always_deny])
            adapter = SemanticKernelAdapter(guard, terminate_on_deny=False)
            kernel, captured = _make_kernel_and_capture()
            adapter.register(kernel)

            context = _make_context()
            mock_next = AsyncMock()
            await captured["filter"](context, mock_next)

            # Tool should still be denied
            assert isinstance(context.function_result, mock_fr_cls)
            assert "DENIED" in str(context.function_result.value)
            # next() should NOT have been called
            mock_next.assert_not_called()
        finally:
            cleanup()

    async def test_terminate_on_deny_true_explicit(self):
        """Explicit terminate_on_deny=True behaves same as default."""
        _, cleanup = _install_sk_mocks()
        try:

            @precondition("*")
            def always_deny(tool_call):
                return Decision.fail("not allowed")

            guard = _make_guard(rules=[always_deny])
            adapter = SemanticKernelAdapter(guard, terminate_on_deny=True)
            kernel, captured = _make_kernel_and_capture()
            adapter.register(kernel)

            context = _make_context()
            await captured["filter"](context, AsyncMock())

            assert context.terminate is True
        finally:
            cleanup()

    async def test_allowed_calls_unaffected_by_terminate_on_deny(self):
        """terminate_on_deny only affects denied calls; allowed calls don't set terminate."""
        _, cleanup = _install_sk_mocks()
        try:
            guard = _make_guard()
            adapter = SemanticKernelAdapter(guard, terminate_on_deny=False)
            kernel, captured = _make_kernel_and_capture()
            adapter.register(kernel)

            context = _make_context()

            async def mock_next(ctx):
                ctx.function_result = "success"

            await captured["filter"](context, mock_next)

            assert context.terminate is False
        finally:
            cleanup()

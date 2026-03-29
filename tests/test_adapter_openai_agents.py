"""Tests for OpenAIAgentsAdapter."""

from __future__ import annotations

from edictum import Decision, Edictum, precondition
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
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


class TestOpenAIAgentsAdapter:
    async def test_allow_returns_correct_format(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard, session_id="test-session")
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={"key": "value"},
            call_id="call-1",
        )
        assert result is None  # None means allow

    async def test_deny_returns_correct_format(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied")

        guard = make_guard(rules=[always_deny])
        adapter = OpenAIAgentsAdapter(guard)
        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert result is not None
        assert result.startswith("DENIED:")
        assert "denied" in result

    async def test_pending_state_management(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)

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
        adapter = OpenAIAgentsAdapter(guard)

        await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        assert "call-1" not in adapter._pending

    async def test_post_without_pending_returns_empty(self):
        from edictum.findings import PostCallResult

        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)
        result = await adapter._post(call_id="unknown")
        assert isinstance(result, PostCallResult)
        assert result.postconditions_passed is True

    async def test_call_index_increments(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._pre(tool_name="T", tool_input={}, call_id="call-2")
        assert adapter._call_index == 2

    async def test_observe_mode_would_deny(self):
        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("would be denied")

        sink = NullAuditSink()
        guard = make_guard(mode="observe", rules=[always_deny], audit_sink=sink)
        adapter = OpenAIAgentsAdapter(guard)

        result = await adapter._pre(
            tool_name="TestTool",
            tool_input={},
            call_id="call-1",
        )
        # Should allow through (None)
        assert result is None
        # Should have CALL_WOULD_DENY audit
        assert any(e.action == AuditAction.CALL_WOULD_DENY for e in sink.events)
        # Pending should exist (tool will execute)
        assert "call-1" in adapter._pending

    async def test_audit_events_emitted(self):
        sink = NullAuditSink()
        guard = make_guard(audit_sink=sink)
        adapter = OpenAIAgentsAdapter(guard)

        await adapter._pre(tool_name="T", tool_input={}, call_id="call-1")
        await adapter._post(call_id="call-1", tool_response="ok")

        actions = [e.action for e in sink.events]
        assert AuditAction.CALL_ALLOWED in actions
        assert AuditAction.CALL_EXECUTED in actions

    async def test_tool_success_detection(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)

        assert adapter._check_tool_success("TestTool", None) is True
        assert adapter._check_tool_success("TestTool", "ok") is True
        assert adapter._check_tool_success("TestTool", "Error: something failed") is False
        assert adapter._check_tool_success("TestTool", "fatal: not a git repo") is False

    async def test_public_api_returns_framework_native(self):
        """as_guardrails() returns a tuple of 2 callables (without importing framework)."""
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)

        # We cannot call as_guardrails() without the agents framework installed,
        # so we verify the method exists and the internal _pre/_post are callable
        assert callable(adapter._pre)
        assert callable(adapter._post)
        assert hasattr(adapter, "as_guardrails")

    async def test_session_id_default(self):
        guard = make_guard()
        adapter = OpenAIAgentsAdapter(guard)
        assert adapter.session_id  # should be a UUID string

    async def test_deny_helper_format(self):
        result = OpenAIAgentsAdapter._deny("test reason")
        assert result == "DENIED: test reason"


class TestAsGuardrailsRegression:
    """Regression tests for as_guardrails() signature fix (v0.5.2).

    The adapter previously used @tool_input_guardrail/@tool_output_guardrail
    decorators which created 3-arg functions (context, agent, data), but the
    SDK's ToolInputGuardrail.run() calls guardrail_function(data) with 1 arg.
    """

    async def test_as_guardrails_returns_correct_types(self):
        """as_guardrails() should return ToolInputGuardrail and ToolOutputGuardrail."""
        import sys
        from types import ModuleType, SimpleNamespace

        # Mock the agents SDK module
        mock_agents = ModuleType("agents")
        mock_tool_guardrails = ModuleType("agents.tool_guardrails")

        class MockToolInputGuardrail:
            def __init__(self, guardrail_function, name=None):
                self.guardrail_function = guardrail_function
                self.name = name

        class MockToolOutputGuardrail:
            def __init__(self, guardrail_function, name=None):
                self.guardrail_function = guardrail_function
                self.name = name

        class MockToolGuardrailFunctionOutput:
            @staticmethod
            def reject_content(reason):
                return SimpleNamespace(action="reject", reason=reason)

            @staticmethod
            def allow():
                return SimpleNamespace(action="allow")

        mock_agents.ToolGuardrailFunctionOutput = MockToolGuardrailFunctionOutput
        mock_tool_guardrails.ToolInputGuardrail = MockToolInputGuardrail
        mock_tool_guardrails.ToolInputGuardrailData = object
        mock_tool_guardrails.ToolOutputGuardrail = MockToolOutputGuardrail
        mock_tool_guardrails.ToolOutputGuardrailData = object

        orig_agents = sys.modules.get("agents")
        orig_tg = sys.modules.get("agents.tool_guardrails")
        sys.modules["agents"] = mock_agents
        sys.modules["agents.tool_guardrails"] = mock_tool_guardrails

        try:
            guard = make_guard()
            adapter = OpenAIAgentsAdapter(guard)
            input_gr, output_gr = adapter.as_guardrails()

            assert isinstance(input_gr, MockToolInputGuardrail)
            assert isinstance(output_gr, MockToolOutputGuardrail)
            assert input_gr.name == "edictum_input_guardrail"
            assert output_gr.name == "edictum_output_guardrail"
        finally:
            if orig_agents is not None:
                sys.modules["agents"] = orig_agents
            else:
                sys.modules.pop("agents", None)
            if orig_tg is not None:
                sys.modules["agents.tool_guardrails"] = orig_tg
            else:
                sys.modules.pop("agents.tool_guardrails", None)

    async def test_as_guardrails_functions_accept_one_arg(self):
        """Guardrail functions should accept 1 arg (data), not 3 (context, agent, data)."""
        import inspect
        import sys
        from types import ModuleType, SimpleNamespace

        # Mock the agents SDK module
        mock_agents = ModuleType("agents")
        mock_tool_guardrails = ModuleType("agents.tool_guardrails")

        class MockToolInputGuardrail:
            def __init__(self, guardrail_function, name=None):
                self.guardrail_function = guardrail_function
                self.name = name

        class MockToolOutputGuardrail:
            def __init__(self, guardrail_function, name=None):
                self.guardrail_function = guardrail_function
                self.name = name

        class MockToolGuardrailFunctionOutput:
            @staticmethod
            def reject_content(reason):
                return SimpleNamespace(action="reject", reason=reason)

            @staticmethod
            def allow():
                return SimpleNamespace(action="allow")

        mock_agents.ToolGuardrailFunctionOutput = MockToolGuardrailFunctionOutput
        mock_tool_guardrails.ToolInputGuardrail = MockToolInputGuardrail
        mock_tool_guardrails.ToolInputGuardrailData = object
        mock_tool_guardrails.ToolOutputGuardrail = MockToolOutputGuardrail
        mock_tool_guardrails.ToolOutputGuardrailData = object

        orig_agents = sys.modules.get("agents")
        orig_tg = sys.modules.get("agents.tool_guardrails")
        sys.modules["agents"] = mock_agents
        sys.modules["agents.tool_guardrails"] = mock_tool_guardrails

        try:
            guard = make_guard()
            adapter = OpenAIAgentsAdapter(guard)
            input_gr, output_gr = adapter.as_guardrails()

            # Verify function signatures accept exactly 1 parameter (data)
            input_sig = inspect.signature(input_gr.guardrail_function)
            output_sig = inspect.signature(output_gr.guardrail_function)
            assert len(input_sig.parameters) == 1, (
                f"Input guardrail should accept 1 arg, got {len(input_sig.parameters)}"
            )
            assert len(output_sig.parameters) == 1, (
                f"Output guardrail should accept 1 arg, got {len(output_sig.parameters)}"
            )
        finally:
            if orig_agents is not None:
                sys.modules["agents"] = orig_agents
            else:
                sys.modules.pop("agents", None)
            if orig_tg is not None:
                sys.modules["agents.tool_guardrails"] = orig_tg
            else:
                sys.modules.pop("agents.tool_guardrails", None)

    async def test_as_guardrails_input_denies(self):
        """Input guardrail should block when precondition fails."""
        import json
        import sys
        from types import ModuleType, SimpleNamespace

        @precondition("*")
        def always_deny(tool_call):
            return Decision.fail("denied by policy")

        # Mock the agents SDK module
        mock_agents = ModuleType("agents")
        mock_tool_guardrails = ModuleType("agents.tool_guardrails")

        class MockToolInputGuardrail:
            def __init__(self, guardrail_function, name=None):
                self.guardrail_function = guardrail_function
                self.name = name

        class MockToolOutputGuardrail:
            def __init__(self, guardrail_function, name=None):
                self.guardrail_function = guardrail_function
                self.name = name

        class MockToolGuardrailFunctionOutput:
            @staticmethod
            def reject_content(reason):
                return SimpleNamespace(action="reject", reason=reason)

            @staticmethod
            def allow():
                return SimpleNamespace(action="allow")

        mock_agents.ToolGuardrailFunctionOutput = MockToolGuardrailFunctionOutput
        mock_tool_guardrails.ToolInputGuardrail = MockToolInputGuardrail
        mock_tool_guardrails.ToolInputGuardrailData = object
        mock_tool_guardrails.ToolOutputGuardrail = MockToolOutputGuardrail
        mock_tool_guardrails.ToolOutputGuardrailData = object

        orig_agents = sys.modules.get("agents")
        orig_tg = sys.modules.get("agents.tool_guardrails")
        sys.modules["agents"] = mock_agents
        sys.modules["agents.tool_guardrails"] = mock_tool_guardrails

        try:
            guard = make_guard(rules=[always_deny])
            adapter = OpenAIAgentsAdapter(guard)
            input_gr, _ = adapter.as_guardrails()

            # Create mock data with 1-arg calling convention
            mock_data = SimpleNamespace(
                context=SimpleNamespace(
                    tool_name="TestTool",
                    tool_arguments=json.dumps({"key": "value"}),
                    tool_call_id="call-1",
                ),
            )

            result = await input_gr.guardrail_function(mock_data)
            assert result.action == "reject"
            assert "denied by policy" in result.reason
        finally:
            if orig_agents is not None:
                sys.modules["agents"] = orig_agents
            else:
                sys.modules.pop("agents", None)
            if orig_tg is not None:
                sys.modules["agents.tool_guardrails"] = orig_tg
            else:
                sys.modules.pop("agents.tool_guardrails", None)

    async def test_as_guardrails_input_allows(self):
        """Input guardrail should allow when preconditions pass."""
        import json
        import sys
        from types import ModuleType, SimpleNamespace

        # Mock the agents SDK module
        mock_agents = ModuleType("agents")
        mock_tool_guardrails = ModuleType("agents.tool_guardrails")

        class MockToolInputGuardrail:
            def __init__(self, guardrail_function, name=None):
                self.guardrail_function = guardrail_function
                self.name = name

        class MockToolOutputGuardrail:
            def __init__(self, guardrail_function, name=None):
                self.guardrail_function = guardrail_function
                self.name = name

        class MockToolGuardrailFunctionOutput:
            @staticmethod
            def reject_content(reason):
                return SimpleNamespace(action="reject", reason=reason)

            @staticmethod
            def allow():
                return SimpleNamespace(action="allow")

        mock_agents.ToolGuardrailFunctionOutput = MockToolGuardrailFunctionOutput
        mock_tool_guardrails.ToolInputGuardrail = MockToolInputGuardrail
        mock_tool_guardrails.ToolInputGuardrailData = object
        mock_tool_guardrails.ToolOutputGuardrail = MockToolOutputGuardrail
        mock_tool_guardrails.ToolOutputGuardrailData = object

        orig_agents = sys.modules.get("agents")
        orig_tg = sys.modules.get("agents.tool_guardrails")
        sys.modules["agents"] = mock_agents
        sys.modules["agents.tool_guardrails"] = mock_tool_guardrails

        try:
            guard = make_guard()
            adapter = OpenAIAgentsAdapter(guard)
            input_gr, _ = adapter.as_guardrails()

            mock_data = SimpleNamespace(
                context=SimpleNamespace(
                    tool_name="TestTool",
                    tool_arguments=json.dumps({"key": "value"}),
                    tool_call_id="call-1",
                ),
            )

            result = await input_gr.guardrail_function(mock_data)
            assert result.action == "allow"
        finally:
            if orig_agents is not None:
                sys.modules["agents"] = orig_agents
            else:
                sys.modules.pop("agents", None)
            if orig_tg is not None:
                sys.modules["agents.tool_guardrails"] = orig_tg
            else:
                sys.modules.pop("agents.tool_guardrails", None)

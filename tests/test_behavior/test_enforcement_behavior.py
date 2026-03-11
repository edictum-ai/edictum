"""Behavior tests for enforcement paths.

When the pipeline denies a tool call, the adapter must actually prevent execution.
Tests that deny decisions are enforced end-to-end, not silently swallowed.
"""

from __future__ import annotations

from types import SimpleNamespace

from edictum import Edictum, Verdict, postcondition, precondition
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _make_deny_guard(**extra):
    @precondition("*")
    def always_deny(envelope):
        return Verdict.fail("contract violation: access denied")

    defaults = {
        "environment": "test",
        "contracts": [always_deny],
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(extra)
    return Edictum(**defaults)


class TestPreconditionDenyEnforcement:
    """Precondition deny must propagate through every adapter."""

    async def test_crewai_deny_returns_reason_string(self):
        """CrewAI _before_hook must return a 'DENIED: ...' string on deny."""
        from edictum.adapters.crewai import CrewAIAdapter

        guard = _make_deny_guard()
        adapter = CrewAIAdapter(guard)
        ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, agent=None, task=None)
        result = await adapter._before_hook(ctx)
        assert (
            isinstance(result, str) and "DENIED" in result
        ), f"CrewAI must return 'DENIED: ...' string on deny (not {type(result).__name__})"

    async def test_openai_deny_returns_denied_string(self):
        """OpenAI _pre must return a DENIED: string on deny."""
        from edictum.adapters.openai_agents import OpenAIAgentsAdapter

        guard = _make_deny_guard()
        adapter = OpenAIAgentsAdapter(guard)
        result = await adapter._pre("TestTool", {}, "call-1")
        assert result is not None
        assert "DENIED" in result

    async def test_langchain_deny_blocks_execution(self):
        """LangChain must produce a denial response, not None."""
        from unittest.mock import MagicMock

        from edictum.adapters.langchain import LangChainAdapter

        guard = _make_deny_guard()
        adapter = LangChainAdapter(guard)
        request = MagicMock()
        request.tool_call = {"name": "TestTool", "args": {}, "id": "tc-1"}
        result = await adapter._pre_tool_call(request)
        assert result is not None, "LangChain must not return None on deny"


class TestPostconditionDenyEnforcement:
    """Postcondition effect=deny must not silently degrade to warn."""

    async def test_postcondition_deny_is_reflected_in_post_result(self):
        """When a postcondition has effect=deny, post result must indicate failure."""

        @postcondition("TestTool")
        def deny_output(envelope, result):
            return Verdict.fail("output contains violation")

        deny_output._edictum_effect = "deny"

        sink = NullAuditSink()
        guard = Edictum(
            environment="test",
            contracts=[deny_output],
            audit_sink=sink,
            backend=MemoryBackend(),
        )

        from edictum.adapters.openai_agents import OpenAIAgentsAdapter

        adapter = OpenAIAgentsAdapter(guard)

        # Pre must allow (no preconditions)
        await adapter._pre("TestTool", {}, "call-1")

        # Post must reflect the denial
        post_result = await adapter._post("call-1", "violation data")
        assert post_result is not None
        assert (
            post_result.postconditions_passed is False
        ), "Postcondition with effect=deny must report postconditions_passed=False"

    async def test_postcondition_deny_output_guardrail_rejects(self):
        """Output guardrail must return reject (not allow) when postcondition has effect=deny."""
        import sys
        from types import ModuleType

        @postcondition("TestTool")
        def deny_output(envelope, result):
            return Verdict.fail("output contains violation")

        deny_output._edictum_effect = "deny"

        guard = Edictum(
            environment="test",
            tools={"TestTool": {"side_effect": "pure"}},
            contracts=[deny_output],
            audit_sink=NullAuditSink(),
            backend=MemoryBackend(),
        )

        # Mock the agents SDK
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
            from edictum.adapters.openai_agents import OpenAIAgentsAdapter

            adapter = OpenAIAgentsAdapter(guard)
            _, output_gr = adapter.as_guardrails()

            # Pre-execute to create pending state
            await adapter._pre("TestTool", {}, "call-1")

            # Call output guardrail with mock data
            mock_data = SimpleNamespace(
                context=SimpleNamespace(tool_call_id="call-1"),
                output="violation data",
            )
            result = await output_gr.guardrail_function(mock_data)

            assert (
                result.action == "reject"
            ), f"Output guardrail must reject when postcondition has effect=deny, but got action={result.action!r}"
        finally:
            if orig_agents is not None:
                sys.modules["agents"] = orig_agents
            else:
                sys.modules.pop("agents", None)
            if orig_tg is not None:
                sys.modules["agents.tool_guardrails"] = orig_tg
            else:
                sys.modules.pop("agents.tool_guardrails", None)


class TestObserveModeEnforcement:
    """Observe mode must convert deny to allow, not silently skip contracts."""

    async def test_observe_mode_logs_would_deny(self):
        """In observe mode, denied calls must emit CALL_WOULD_DENY audit events."""
        sink = NullAuditSink()
        guard = _make_deny_guard(audit_sink=sink, mode="observe")

        from edictum.adapters.crewai import CrewAIAdapter

        adapter = CrewAIAdapter(guard)
        ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, agent=None, task=None)
        result = await adapter._before_hook(ctx)

        # Observe mode: must allow
        assert result is None, "Observe mode must allow (return None)"

        # Must have logged would_deny
        would_deny_events = [e for e in sink.events if e.action == AuditAction.CALL_WOULD_DENY]
        assert len(would_deny_events) >= 1, "Observe mode must emit CALL_WOULD_DENY audit event"

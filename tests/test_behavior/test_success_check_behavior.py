"""Behavior tests for success_check parameter.

Verifies that a custom success_check callable changes the observable
tool_success value, which cascades into session counting and audit events.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Edictum
from edictum.audit import AuditAction
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


class TestCustomSuccessCheckChangesToolSuccess:
    """success_check must change the tool_success value in audit events."""

    async def test_custom_checker_marks_http_error_as_failure(self):
        """A result the default heuristic misses is caught by custom checker."""
        from edictum.adapters.crewai import CrewAIAdapter

        def http_checker(tool_name, result):
            if isinstance(result, dict) and result.get("status", 200) >= 400:
                return False
            return True

        sink = NullAuditSink()
        guard = _make_guard(success_check=http_checker, audit_sink=sink)
        adapter = CrewAIAdapter(guard)

        # Pre-hook
        before_ctx = SimpleNamespace(tool_name="api_call", tool_input={}, agent=None, task=None)
        await adapter._before_hook(before_ctx)

        # After-hook with HTTP 500 response
        after_ctx = SimpleNamespace(
            tool_name="api_call",
            tool_input={},
            tool_result={"status": 500, "error": "Internal Server Error"},
            agent=None,
            task=None,
        )
        await adapter._after_hook(after_ctx)

        failed_events = [e for e in sink.events if e.action == AuditAction.CALL_FAILED]
        assert (
            len(failed_events) == 1
        ), f"Custom success_check should mark HTTP 500 as failure, but got {len(failed_events)} CALL_FAILED events"

    async def test_default_heuristic_misses_http_error(self):
        """Without custom checker, HTTP 500 dict is wrongly counted as success."""
        from edictum.adapters.crewai import CrewAIAdapter

        sink = NullAuditSink()
        guard = _make_guard(audit_sink=sink)
        adapter = CrewAIAdapter(guard)

        before_ctx = SimpleNamespace(tool_name="api_call", tool_input={}, agent=None, task=None)
        await adapter._before_hook(before_ctx)

        after_ctx = SimpleNamespace(
            tool_name="api_call",
            tool_input={},
            tool_result={"status": 500, "error": "Internal Server Error"},
            agent=None,
            task=None,
        )
        await adapter._after_hook(after_ctx)

        executed_events = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert len(executed_events) == 1, (
            "Default heuristic should miss HTTP 500 (no is_error key), "
            f"but got {len(executed_events)} CALL_EXECUTED events"
        )


class TestDefaultHeuristicStillWorks:
    """When success_check is not provided, the default heuristic applies."""

    async def test_error_prefix_detected_without_custom_checker(self):
        from edictum.adapters.openai_agents import OpenAIAgentsAdapter

        sink = NullAuditSink()
        guard = _make_guard(audit_sink=sink)
        adapter = OpenAIAgentsAdapter(guard)

        await adapter._pre("TestTool", {}, "call-1")
        await adapter._post("call-1", "Error: something went wrong")

        failed_events = [e for e in sink.events if e.action == AuditAction.CALL_FAILED]
        assert len(failed_events) == 1

    async def test_is_error_dict_detected_without_custom_checker(self):
        from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter

        sink = NullAuditSink()
        guard = _make_guard(audit_sink=sink)
        adapter = ClaudeAgentSDKAdapter(guard)

        await adapter._pre_tool_use("TestTool", {}, "tc-1")
        await adapter._post_tool_use(tool_use_id="tc-1", tool_response={"is_error": True, "message": "fail"})

        failed_events = [e for e in sink.events if e.action == AuditAction.CALL_FAILED]
        assert len(failed_events) == 1


class TestSuccessCheckAffectsSessionCounting:
    """Custom success_check must change session execution counts."""

    async def test_failed_call_not_counted_as_success_in_session(self):
        from edictum.adapters.openai_agents import OpenAIAgentsAdapter

        def always_fail(tool_name, result):
            return False

        backend = MemoryBackend()
        guard = _make_guard(success_check=always_fail, backend=backend)
        adapter = OpenAIAgentsAdapter(guard)

        await adapter._pre("TestTool", {}, "call-1")
        await adapter._post("call-1", "looks fine")

        # Session should record execution with success=False
        exec_count = await adapter._session.execution_count()
        assert exec_count == 1, "Execution should still be recorded"

        # Check consecutive failures incremented
        consec_fail = int(await backend.get(f"s:{adapter.session_id}:consec_fail") or 0)
        assert consec_fail == 1, "Consecutive failures should be 1 when success_check returns False"


class TestSuccessCheckViaRun:
    """success_check works through Edictum.run() (framework-agnostic path)."""

    async def test_run_uses_custom_success_check(self):
        from edictum import EdictumToolError

        def http_checker(tool_name, result):
            if isinstance(result, dict) and result.get("status", 200) >= 400:
                return False
            return True

        sink = NullAuditSink()
        guard = _make_guard(success_check=http_checker, audit_sink=sink)

        def fake_tool(**kwargs):
            return {"status": 500, "error": "Internal Server Error"}

        with pytest.raises(EdictumToolError):
            await guard.run("api_call", {}, fake_tool)

        failed_events = [e for e in sink.events if e.action == AuditAction.CALL_FAILED]
        assert len(failed_events) == 1

    async def test_run_without_custom_checker_treats_dict_as_success(self):
        sink = NullAuditSink()
        guard = _make_guard(audit_sink=sink)

        def fake_tool(**kwargs):
            return {"status": 500, "error": "Internal Server Error"}

        await guard.run("api_call", {}, fake_tool)

        executed_events = [e for e in sink.events if e.action == AuditAction.CALL_EXECUTED]
        assert len(executed_events) == 1


class TestSuccessCheckFromYamlString:
    """success_check forwarded through from_yaml_string factory."""

    async def test_from_yaml_string_forwards_success_check(self):
        yaml_content = """\
apiVersion: edictum/v1
kind: ContractBundle
metadata:
  name: test-bundle
defaults:
  mode: enforce
contracts:
  - id: dummy
    type: pre
    tool: noop
    when:
      tool_name: { equals: noop }
    then:
      effect: deny
      message: "no-op"
"""

        def custom_checker(tool_name, result):
            return False

        guard = Edictum.from_yaml_string(
            yaml_content,
            success_check=custom_checker,
            audit_sink=NullAuditSink(),
        )
        assert guard._success_check is custom_checker

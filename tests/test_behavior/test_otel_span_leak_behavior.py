"""Behavior tests for OTel span lifecycle — no span leaks on exceptions or denials.

Verifies span.end() is always called even when pipeline raises, adapters block,
or Nanobot hits the no-backend approval path.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from edictum import Decision, Edictum, precondition
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink


def _make_guard(**kwargs):
    defaults = {"environment": "test", "audit_sink": NullAuditSink(), "backend": MemoryBackend()}
    defaults.update(kwargs)
    return Edictum(**defaults)


# --- Adapter pre/post helpers (copied from test_adapter_parity.py) ---


async def _openai_pre(a, **kw):
    return await a._pre(kw.get("tool_name", "TestTool"), kw.get("args", {}), "call-1")


async def _openai_post(a, result="ok"):
    return await a._post("call-1", result)


async def _langchain_pre(a, **kw):
    r = MagicMock()
    r.tool_call = {"name": kw.get("tool_name", "TestTool"), "args": kw.get("args", {}), "id": "tc-1"}
    return await a._pre_tool_call(r)


async def _langchain_post(a, result="ok"):
    r = MagicMock()
    r.tool_call = {"name": "TestTool", "args": {}, "id": "tc-1"}
    return await a._post_tool_call(r, result)


async def _crewai_pre(a, **kw):
    ctx = SimpleNamespace(
        tool_name=kw.get("tool_name", "TestTool"),
        tool_input=kw.get("args", {}),
        agent=None,
        task=None,
    )
    return await a._before_hook(ctx)


async def _crewai_post(a, result="ok"):
    ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, tool_result=result, agent=None, task=None)
    return await a._after_hook(ctx)


async def _claude_sdk_pre(a, **kw):
    return await a._pre_tool_use(kw.get("tool_name", "TestTool"), kw.get("args", {}), "tc-1")


async def _claude_sdk_post(a, result="ok"):
    return await a._post_tool_use(tool_use_id="tc-1", tool_response=result)


async def _agno_pre(a, **kw):
    return await a._pre(kw.get("tool_name", "TestTool"), kw.get("args", {}), "call-1")


async def _agno_post(a, result="ok"):
    return await a._post("call-1", result)


async def _sk_pre(a, **kw):
    return await a._pre(kw.get("tool_name", "TestTool"), kw.get("args", {}), "call-1")


async def _sk_post(a, result="ok"):
    return await a._post("call-1", result)


async def _adk_pre(a, **kw):
    return await a._pre(kw.get("tool_name", "TestTool"), kw.get("args", {}), "call-1")


async def _adk_post(a, result="ok"):
    return await a._post("call-1", result)


def _all_configs():
    from edictum.adapters.agno import AgnoAdapter
    from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
    from edictum.adapters.crewai import CrewAIAdapter
    from edictum.adapters.google_adk import GoogleADKAdapter
    from edictum.adapters.langchain import LangChainAdapter
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter
    from edictum.adapters.semantic_kernel import SemanticKernelAdapter

    return [
        ("OpenAI", OpenAIAgentsAdapter, _openai_pre, _openai_post),
        ("LangChain", LangChainAdapter, _langchain_pre, _langchain_post),
        ("CrewAI", CrewAIAdapter, _crewai_pre, _crewai_post),
        ("ClaudeSDK", ClaudeAgentSDKAdapter, _claude_sdk_pre, _claude_sdk_post),
        ("Agno", AgnoAdapter, _agno_pre, _agno_post),
        ("SK", SemanticKernelAdapter, _sk_pre, _sk_post),
        ("GoogleADK", GoogleADKAdapter, _adk_pre, _adk_post),
    ]


CONFIGS = _all_configs()
IDS = [c[0] for c in CONFIGS]


class TestAdapterSpanEndOnPreRaise:
    """span.end() must be called even when pipeline.pre_execute() raises."""

    @pytest.mark.parametrize("name,cls,pre_fn,post_fn", CONFIGS, ids=IDS)
    async def test_span_ended_when_pre_execute_raises(self, name, cls, pre_fn, post_fn):
        guard = _make_guard()
        adapter = cls(guard)
        mock_span = MagicMock()
        with (
            patch.object(guard.telemetry, "start_tool_span", return_value=mock_span),
            patch.object(adapter._pipeline, "pre_execute", side_effect=RuntimeError("boom")),
        ):
            with pytest.raises(RuntimeError, match="boom"):
                await pre_fn(adapter)
        mock_span.end.assert_called_once()


class TestAdapterSpanEndOnPostRaise:
    """span.end() must be called even when pipeline.post_execute() raises."""

    @pytest.mark.parametrize("name,cls,pre_fn,post_fn", CONFIGS, ids=IDS)
    async def test_span_ended_when_post_execute_raises(self, name, cls, pre_fn, post_fn):
        guard = _make_guard()
        adapter = cls(guard)
        mock_span = MagicMock()
        with patch.object(guard.telemetry, "start_tool_span", return_value=mock_span):
            await pre_fn(adapter)
        with patch.object(adapter._pipeline, "post_execute", side_effect=RuntimeError("post boom")):
            with pytest.raises(RuntimeError, match="post boom"):
                await post_fn(adapter, result="ok")
        assert mock_span.end.call_count >= 1


class TestGuardRunSpanEnd:
    """guard.run() ends span even when pipeline raises."""

    async def test_guard_run_span_ended_on_pipeline_raise(self):
        guard = _make_guard()
        mock_span = MagicMock()
        with (
            patch.object(guard.telemetry, "start_tool_span", return_value=mock_span),
            patch("edictum.CheckPipeline.pre_execute", side_effect=RuntimeError("crash")),
        ):
            with pytest.raises(RuntimeError, match="crash"):
                await guard.run("TestTool", {}, lambda: "ok")
        mock_span.end.assert_called_once()


# --- Nanobot span and denial path tests ---


def _make_approval_contract():
    @precondition("*")
    def requires_approval(tool_call):
        return Decision.fail("needs approval")

    requires_approval._edictum_effect = "ask"
    requires_approval._edictum_timeout = 10
    requires_approval._edictum_timeout_action = "block"
    return requires_approval


@pytest.mark.security
class TestNanobotNoBackendDenial:
    """Nanobot no-backend approval path emits correct audit and callbacks."""

    async def test_no_backend_emits_call_denied(self):
        from edictum.adapters.nanobot import GovernedToolRegistry

        sink = NullAuditSink()
        guard = _make_guard(rules=[_make_approval_contract()], audit_sink=sink)
        inner = MagicMock()
        inner.execute = AsyncMock(return_value="ok")
        registry = GovernedToolRegistry(inner, guard)
        result = await registry.execute("TestTool", {})
        assert "[DENIED]" in result
        deny_events = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
        assert len(deny_events) >= 1, f"Expected CALL_DENIED, got {[e.action.value for e in sink.events]}"

    async def test_no_backend_calls_record_denial(self):
        from edictum.adapters.nanobot import GovernedToolRegistry

        guard = _make_guard(rules=[_make_approval_contract()])
        inner = MagicMock()
        inner.execute = AsyncMock(return_value="ok")
        registry = GovernedToolRegistry(inner, guard)
        with patch.object(guard.telemetry, "record_denial") as mock_denial:
            await registry.execute("TestTool", {})
            mock_denial.assert_called_once()

    async def test_no_backend_fires_on_block(self):
        from edictum.adapters.nanobot import GovernedToolRegistry

        on_block = MagicMock()
        guard = _make_guard(rules=[_make_approval_contract()], on_block=on_block)
        inner = MagicMock()
        inner.execute = AsyncMock(return_value="ok")
        registry = GovernedToolRegistry(inner, guard)
        await registry.execute("TestTool", {})
        on_block.assert_called_once()
        assert "no approval backend" in on_block.call_args[0][1].lower()


class TestNanobotSpanEndOnDeny:
    """Nanobot execute() ends span even on block path (try/finally)."""

    async def test_nanobot_execute_span_ended_on_block(self):
        from edictum.adapters.nanobot import GovernedToolRegistry

        @precondition("*")
        def block(tool_call):
            return Decision.fail("denied")

        guard = _make_guard(rules=[block])
        inner = MagicMock()
        registry = GovernedToolRegistry(inner, guard)
        mock_span = MagicMock()
        with patch.object(guard.telemetry, "start_tool_span", return_value=mock_span):
            await registry.execute("TestTool", {})
        mock_span.end.assert_called_once()

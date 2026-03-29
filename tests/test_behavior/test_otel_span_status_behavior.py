"""Behavior tests for OTel span status helpers and adapter integration."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from edictum import Decision, Edictum, precondition
from edictum._runner import _ERROR_ACTIONS
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

try:
    import opentelemetry  # noqa: F401

    HAS_OTEL = True
except ImportError:
    HAS_OTEL = False


def _make_guard(**kwargs):
    defaults = {
        "environment": "test",
        "audit_sink": NullAuditSink(),
        "backend": MemoryBackend(),
    }
    defaults.update(kwargs)
    return Edictum(**defaults)


# --- Test 1: _NoOpSpan.set_status ---


def test_noopspan_set_status_accepts_description():
    """_NoOpSpan.set_status accepts optional description argument."""
    from edictum.telemetry import _NoOpSpan

    span = _NoOpSpan()
    span.set_status("OK", "description")  # must not raise


# --- Test 2: set_span_error / set_span_ok helpers ---


@pytest.mark.skipif(not HAS_OTEL, reason="OpenTelemetry not installed")
def test_set_span_error_calls_set_status():
    """set_span_error sets ERROR status on the span."""
    from opentelemetry.trace import StatusCode

    from edictum.telemetry import GovernanceTelemetry

    telemetry = GovernanceTelemetry()
    mock_span = MagicMock()
    telemetry.set_span_error(mock_span, "some reason")
    mock_span.set_status.assert_called_once_with(StatusCode.ERROR, "some reason")


@pytest.mark.skipif(not HAS_OTEL, reason="OpenTelemetry not installed")
def test_set_span_ok_calls_set_status():
    """set_span_ok sets OK status on the span."""
    from opentelemetry.trace import StatusCode

    from edictum.telemetry import GovernanceTelemetry

    telemetry = GovernanceTelemetry()
    mock_span = MagicMock()
    telemetry.set_span_ok(mock_span)
    mock_span.set_status.assert_called_once_with(StatusCode.OK)


def test_set_span_error_noop_without_otel():
    """set_span_error does nothing when OTel is not installed."""
    from edictum.telemetry import GovernanceTelemetry

    telemetry = GovernanceTelemetry()
    mock_span = MagicMock()
    with patch("edictum.telemetry._HAS_OTEL", False):
        telemetry.set_span_error(mock_span, "reason")
    mock_span.set_status.assert_not_called()


def test_set_span_ok_noop_without_otel():
    """set_span_ok does nothing when OTel is not installed."""
    from edictum.telemetry import GovernanceTelemetry

    telemetry = GovernanceTelemetry()
    mock_span = MagicMock()
    with patch("edictum.telemetry._HAS_OTEL", False):
        telemetry.set_span_ok(mock_span)
    mock_span.set_status.assert_not_called()


# --- Test 3: _ERROR_ACTIONS frozenset ---


@pytest.mark.parametrize(
    "action,should_error",
    [
        (AuditAction.CALL_DENIED, True),
        (AuditAction.CALL_APPROVAL_DENIED, True),
        (AuditAction.CALL_APPROVAL_TIMEOUT, True),
        (AuditAction.CALL_ALLOWED, False),
        (AuditAction.CALL_EXECUTED, False),
        (AuditAction.CALL_WOULD_DENY, False),
    ],
)
def test_error_actions_coverage(action, should_error):
    """_ERROR_ACTIONS frozenset contains exactly the error audit actions."""
    if should_error:
        assert action.value in _ERROR_ACTIONS
    else:
        assert action.value not in _ERROR_ACTIONS


# --- Adapter pre/post helpers (copied from test_adapter_parity.py) ---


async def _langchain_pre(adapter, tool_name="TestTool", args=None):
    request = MagicMock()
    request.tool_call = {"name": tool_name, "args": args or {}, "id": "tc-1"}
    return await adapter._pre_tool_call(request)


async def _langchain_post(adapter, result="ok"):
    request = MagicMock()
    request.tool_call = {"name": "TestTool", "args": {}, "id": "tc-1"}
    return await adapter._post_tool_call(request, result)


async def _crewai_pre(adapter, tool_name="TestTool", args=None):
    ctx = SimpleNamespace(tool_name=tool_name, tool_input=args or {}, agent=None, task=None)
    return await adapter._before_hook(ctx)


async def _crewai_post(adapter, result="ok"):
    ctx = SimpleNamespace(tool_name="TestTool", tool_input={}, tool_result=result, agent=None, task=None)
    return await adapter._after_hook(ctx)


async def _openai_pre(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-1")


async def _openai_post(adapter, result="ok"):
    return await adapter._post("call-1", result)


async def _claude_sdk_pre(adapter, tool_name="TestTool", args=None):
    return await adapter._pre_tool_use(tool_name, args or {}, "tc-1")


async def _claude_sdk_post(adapter, result="ok"):
    return await adapter._post_tool_use(tool_use_id="tc-1", tool_response=result)


async def _agno_pre(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-1")


async def _agno_post(adapter, result="ok"):
    return await adapter._post("call-1", result)


async def _sk_pre(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-1")


async def _sk_post(adapter, result="ok"):
    return await adapter._post("call-1", result)


async def _adk_pre(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-1")


async def _adk_post(adapter, result="ok"):
    return await adapter._post("call-1", result)


def _all_pre_configs():
    from edictum.adapters.agno import AgnoAdapter
    from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
    from edictum.adapters.crewai import CrewAIAdapter
    from edictum.adapters.google_adk import GoogleADKAdapter
    from edictum.adapters.langchain import LangChainAdapter
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter
    from edictum.adapters.semantic_kernel import SemanticKernelAdapter

    return [
        ("CrewAI", CrewAIAdapter, _crewai_pre),
        ("OpenAI", OpenAIAgentsAdapter, _openai_pre),
        ("LangChain", LangChainAdapter, _langchain_pre),
        ("ClaudeSDK", ClaudeAgentSDKAdapter, _claude_sdk_pre),
        ("Agno", AgnoAdapter, _agno_pre),
        ("SK", SemanticKernelAdapter, _sk_pre),
        ("GoogleADK", GoogleADKAdapter, _adk_pre),
    ]


def _all_pre_post_configs():
    from edictum.adapters.agno import AgnoAdapter
    from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
    from edictum.adapters.crewai import CrewAIAdapter
    from edictum.adapters.google_adk import GoogleADKAdapter
    from edictum.adapters.langchain import LangChainAdapter
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter
    from edictum.adapters.semantic_kernel import SemanticKernelAdapter

    return [
        ("CrewAI", CrewAIAdapter, _crewai_pre, _crewai_post),
        ("OpenAI", OpenAIAgentsAdapter, _openai_pre, _openai_post),
        ("LangChain", LangChainAdapter, _langchain_pre, _langchain_post),
        ("ClaudeSDK", ClaudeAgentSDKAdapter, _claude_sdk_pre, _claude_sdk_post),
        ("Agno", AgnoAdapter, _agno_pre, _agno_post),
        ("SK", SemanticKernelAdapter, _sk_pre, _sk_post),
        ("GoogleADK", GoogleADKAdapter, _adk_pre, _adk_post),
    ]


ALL_PRE = _all_pre_configs()
ALL_PRE_IDS = [c[0] for c in ALL_PRE]
ALL_PRE_POST = _all_pre_post_configs()
ALL_PRE_POST_IDS = [c[0] for c in ALL_PRE_POST]


# --- Test 4: Adapter block path calls set_span_error ---


@pytest.mark.parametrize("name,cls,pre_fn", ALL_PRE, ids=ALL_PRE_IDS)
async def test_adapter_deny_calls_set_span_error(name, cls, pre_fn):
    """All adapters call set_span_error when precondition denies."""

    @precondition("*")
    def block_all(tool_call):
        return Decision.fail("test denial")

    guard = _make_guard(rules=[block_all])
    adapter = cls(guard)

    with patch.object(guard.telemetry, "set_span_error") as mock_error:
        await pre_fn(adapter)
        mock_error.assert_called_once()
        args = mock_error.call_args[0]
        assert "test denial" in args[1]


# --- Test 5: Adapter post path calls set_span_ok on success ---


@pytest.mark.parametrize("name,cls,pre_fn,post_fn", ALL_PRE_POST, ids=ALL_PRE_POST_IDS)
async def test_adapter_post_calls_set_span_ok_on_success(name, cls, pre_fn, post_fn):
    """All adapters call set_span_ok after successful tool execution."""
    guard = _make_guard()
    adapter = cls(guard, session_id="test")

    with patch.object(guard.telemetry, "set_span_ok") as mock_ok:
        await pre_fn(adapter)
        await post_fn(adapter, result="success")
        mock_ok.assert_called_once()


# --- Test 6: Adapter post path calls set_span_error on failure ---


@pytest.mark.parametrize("name,cls,pre_fn,post_fn", ALL_PRE_POST, ids=ALL_PRE_POST_IDS)
async def test_adapter_post_calls_set_span_error_on_failure(name, cls, pre_fn, post_fn):
    """All adapters call set_span_error after failed tool execution."""
    guard = _make_guard()
    adapter = cls(guard, session_id="test")

    with patch.object(guard.telemetry, "set_span_error") as mock_error:
        await pre_fn(adapter)
        await post_fn(adapter, result="Error: something failed")
        mock_error.assert_called_once()
        assert "tool execution failed" in mock_error.call_args[0][1]

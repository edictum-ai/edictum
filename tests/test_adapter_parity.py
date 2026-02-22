"""Adapter parity matrix.

Verifies all adapters handle core scenarios consistently.
Each test class covers one parity dimension.

Note: LangChain handles on_postcondition_warn differently (method param,
not constructor), so callback parity tests only cover CrewAI and OpenAI.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from edictum import Edictum, Principal, Verdict, postcondition, precondition
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


# --- LangChain uses request objects, not raw params ---


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


def _adapter_configs():
    from edictum.adapters.crewai import CrewAIAdapter
    from edictum.adapters.langchain import LangChainAdapter
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter

    def _crewai_deny(r):
        return isinstance(r, str) and "DENIED" in r

    return [
        ("CrewAI", CrewAIAdapter, _crewai_pre, _crewai_post, lambda r: r is None, _crewai_deny),
        ("OpenAI", OpenAIAgentsAdapter, _openai_pre, _openai_post, lambda r: r is None, lambda r: r is not None),
        ("LangChain", LangChainAdapter, _langchain_pre, _langchain_post, lambda r: r is None, lambda r: r is not None),
    ]


CONFIGS = _adapter_configs()
ADAPTER_IDS = [c[0] for c in CONFIGS]


class TestParityAllow:
    """All adapters must allow when no contracts match."""

    @pytest.mark.parametrize("name,cls,pre_fn,post_fn,allow_check,deny_check", CONFIGS, ids=ADAPTER_IDS)
    async def test_allow_path(self, name, cls, pre_fn, post_fn, allow_check, deny_check):
        guard = _make_guard()
        adapter = cls(guard, session_id="test")
        result = await pre_fn(adapter)
        assert allow_check(result), f"{name} did not return allow value"


class TestParityDeny:
    """All adapters must deny when a precondition fails."""

    @pytest.mark.parametrize("name,cls,pre_fn,post_fn,allow_check,deny_check", CONFIGS, ids=ADAPTER_IDS)
    async def test_deny_path(self, name, cls, pre_fn, post_fn, allow_check, deny_check):
        @precondition("*")
        def block_all(envelope):
            return Verdict.fail("not allowed")

        guard = _make_guard(contracts=[block_all])
        adapter = cls(guard)
        result = await pre_fn(adapter)
        assert deny_check(result), f"{name} did not return deny value"


class TestParityDenyReason:
    """All adapters must preserve the denial reason in audit events."""

    @pytest.mark.parametrize("name,cls,pre_fn,post_fn,allow_check,deny_check", CONFIGS, ids=ADAPTER_IDS)
    async def test_deny_reason_in_audit(self, name, cls, pre_fn, post_fn, allow_check, deny_check):
        @precondition("*")
        def block_with_reason(envelope):
            return Verdict.fail("specific reason XYZ")

        sink = NullAuditSink()
        guard = _make_guard(contracts=[block_with_reason], audit_sink=sink)
        adapter = cls(guard)
        await pre_fn(adapter)

        deny_events = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
        assert len(deny_events) >= 1, f"{name} emitted no CALL_DENIED audit event"
        assert "specific reason XYZ" in (
            deny_events[0].reason or ""
        ), f"{name} lost the denial reason. Got: {deny_events[0].reason}"


class TestParityObserve:
    """All adapters must convert deny to allow in observe mode."""

    @pytest.mark.parametrize("name,cls,pre_fn,post_fn,allow_check,deny_check", CONFIGS, ids=ADAPTER_IDS)
    async def test_observe_mode_allows(self, name, cls, pre_fn, post_fn, allow_check, deny_check):
        @precondition("*")
        def block_all(envelope):
            return Verdict.fail("would deny")

        guard = _make_guard(contracts=[block_all], mode="observe")
        adapter = cls(guard)
        result = await pre_fn(adapter)
        assert allow_check(result), f"{name} denied in observe mode (should allow)"


# Callback parity: CrewAI and OpenAI accept on_postcondition_warn in constructor.
# LangChain passes it to wrapper methods instead, tested separately.


def _callback_adapter_configs():
    from edictum.adapters.crewai import CrewAIAdapter
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter

    return [
        ("CrewAI", CrewAIAdapter, _crewai_pre, _crewai_post),
        ("OpenAI", OpenAIAgentsAdapter, _openai_pre, _openai_post),
    ]


CALLBACK_CONFIGS = _callback_adapter_configs()
CALLBACK_IDS = [c[0] for c in CALLBACK_CONFIGS]


class TestParityCallbackCount:
    """Adapters must fire on_postcondition_warn exactly once."""

    @pytest.mark.parametrize("name,cls,pre_fn,post_fn", CALLBACK_CONFIGS, ids=CALLBACK_IDS)
    async def test_callback_fires_once(self, name, cls, pre_fn, post_fn):
        @postcondition("TestTool")
        def detect(envelope, result):
            return Verdict.fail("issue found")

        guard = _make_guard(contracts=[detect])
        callback = MagicMock()
        adapter = cls(guard)
        adapter._on_postcondition_warn = callback

        await pre_fn(adapter)
        await post_fn(adapter)

        assert callback.call_count == 1, f"{name} fired on_postcondition_warn {callback.call_count} times, expected 1"


# --- Pre helpers for adapters with separate pre/post methods ---
# Note: Nanobot uses GovernedToolRegistry which wraps execute() directly
# (no separate pre/post). Nanobot parity is verified in test_adapter_nanobot.py.


async def _claude_sdk_pre(adapter, tool_name="TestTool", args=None):
    return await adapter._pre_tool_use(tool_name, args or {}, "tc-1")


async def _agno_pre(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-1")


async def _sk_pre(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-1")


def _all_adapter_configs():
    from edictum.adapters.agno import AgnoAdapter
    from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
    from edictum.adapters.crewai import CrewAIAdapter
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
    ]


ALL_CONFIGS = _all_adapter_configs()
ALL_ADAPTER_IDS = [c[0] for c in ALL_CONFIGS]


class TestParityOnDeny:
    """All adapters must fire on_deny exactly once when a precondition denies."""

    @pytest.mark.parametrize("name,cls,pre_fn", ALL_CONFIGS, ids=ALL_ADAPTER_IDS)
    async def test_on_deny_fires_once(self, name, cls, pre_fn):
        @precondition("*")
        def block_all(envelope):
            return Verdict.fail("not allowed")

        on_deny = MagicMock()
        guard = _make_guard(contracts=[block_all], on_deny=on_deny)
        adapter = cls(guard)
        await pre_fn(adapter)

        assert on_deny.call_count == 1, f"{name} fired on_deny {on_deny.call_count} times, expected 1"


class TestParityOnAllow:
    """All adapters must fire on_allow exactly once when no contracts deny."""

    @pytest.mark.parametrize("name,cls,pre_fn", ALL_CONFIGS, ids=ALL_ADAPTER_IDS)
    async def test_on_allow_fires_once(self, name, cls, pre_fn):
        on_allow = MagicMock()
        guard = _make_guard(on_allow=on_allow)
        adapter = cls(guard, session_id="test")
        await pre_fn(adapter)

        assert on_allow.call_count == 1, f"{name} fired on_allow {on_allow.call_count} times, expected 1"


# --- Post helpers for adapters with separate pre/post methods ---


async def _claude_sdk_post(adapter, result="ok"):
    return await adapter._post_tool_use(tool_use_id="tc-1", tool_response=result)


async def _agno_post(adapter, result="ok"):
    return await adapter._post("call-1", result)


async def _sk_post(adapter, result="ok"):
    return await adapter._post("call-1", result)


def _all_adapter_pre_post_configs():
    from edictum.adapters.agno import AgnoAdapter
    from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
    from edictum.adapters.crewai import CrewAIAdapter
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
    ]


ALL_PRE_POST_CONFIGS = _all_adapter_pre_post_configs()
ALL_PRE_POST_IDS = [c[0] for c in ALL_PRE_POST_CONFIGS]


class TestParitySuccessCheck:
    """All adapters must respect custom success_check."""

    @pytest.mark.parametrize("name,cls,pre_fn,post_fn", ALL_PRE_POST_CONFIGS, ids=ALL_PRE_POST_IDS)
    async def test_custom_success_check_marks_failure(self, name, cls, pre_fn, post_fn):
        """Custom success_check returning False must produce CALL_FAILED audit."""

        def always_fail(tool_name, result):
            return False

        sink = NullAuditSink()
        guard = _make_guard(success_check=always_fail, audit_sink=sink)
        adapter = cls(guard)

        await pre_fn(adapter)
        await post_fn(adapter, result="looks fine")

        failed_events = [e for e in sink.events if e.action == AuditAction.CALL_FAILED]
        assert len(failed_events) == 1, (
            f"{name} did not emit CALL_FAILED with custom success_check. "
            f"Events: {[e.action.value for e in sink.events]}"
        )


# --- Mutable principal helpers ---


def _is_denied(result) -> bool:
    """Adapter-agnostic check for a denial result."""
    if result is None:
        return False
    if isinstance(result, str):
        return "DENIED" in result
    if isinstance(result, dict):
        hook = result.get("hookSpecificOutput", {})
        return hook.get("permissionDecision") == "deny"
    # LangChain ToolMessage
    content = getattr(result, "content", "")
    return "DENIED" in content


# Second-call pre helpers with fresh call IDs


async def _langchain_pre_2(adapter, tool_name="TestTool", args=None):
    request = MagicMock()
    request.tool_call = {"name": tool_name, "args": args or {}, "id": "tc-2"}
    return await adapter._pre_tool_call(request)


async def _crewai_pre_2(adapter, tool_name="TestTool", args=None):
    ctx = SimpleNamespace(tool_name=tool_name, tool_input=args or {}, agent=None, task=None)
    return await adapter._before_hook(ctx)


async def _openai_pre_2(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-2")


async def _claude_sdk_pre_2(adapter, tool_name="TestTool", args=None):
    return await adapter._pre_tool_use(tool_name, args or {}, "tc-2")


async def _agno_pre_2(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-2")


async def _sk_pre_2(adapter, tool_name="TestTool", args=None):
    return await adapter._pre(tool_name, args or {}, "call-2")


def _all_adapter_configs_with_pre2():
    from edictum.adapters.agno import AgnoAdapter
    from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
    from edictum.adapters.crewai import CrewAIAdapter
    from edictum.adapters.langchain import LangChainAdapter
    from edictum.adapters.openai_agents import OpenAIAgentsAdapter
    from edictum.adapters.semantic_kernel import SemanticKernelAdapter

    return [
        ("CrewAI", CrewAIAdapter, _crewai_pre, _crewai_pre_2),
        ("OpenAI", OpenAIAgentsAdapter, _openai_pre, _openai_pre_2),
        ("LangChain", LangChainAdapter, _langchain_pre, _langchain_pre_2),
        ("ClaudeSDK", ClaudeAgentSDKAdapter, _claude_sdk_pre, _claude_sdk_pre_2),
        ("Agno", AgnoAdapter, _agno_pre, _agno_pre_2),
        ("SK", SemanticKernelAdapter, _sk_pre, _sk_pre_2),
    ]


ALL_CONFIGS_WITH_PRE2 = _all_adapter_configs_with_pre2()
ALL_ADAPTER_WITH_PRE2_IDS = [c[0] for c in ALL_CONFIGS_WITH_PRE2]


class TestParitySetPrincipal:
    """All adapters must update principal after set_principal()."""

    @pytest.mark.parametrize(
        "name,cls,pre_fn,pre_fn_2",
        ALL_CONFIGS_WITH_PRE2,
        ids=ALL_ADAPTER_WITH_PRE2_IDS,
    )
    async def test_set_principal_updates_enforcement(self, name, cls, pre_fn, pre_fn_2):
        @precondition("*")
        def require_admin(envelope):
            if envelope.principal is None or envelope.principal.role != "admin":
                return Verdict.fail("admin required")
            return Verdict.pass_()

        guard = _make_guard(contracts=[require_admin])
        adapter = cls(guard, principal=Principal(role="viewer"))

        # First call: viewer -> denied
        result1 = await pre_fn(adapter)
        assert _is_denied(result1), f"{name} did not deny viewer principal"

        # Mutate principal
        adapter.set_principal(Principal(role="admin"))

        # Second call: admin -> allowed
        result2 = await pre_fn_2(adapter)
        assert not _is_denied(result2), f"{name} denied after set_principal(admin)"


class TestParityPrincipalResolver:
    """All adapters must use principal_resolver when provided."""

    @pytest.mark.parametrize("name,cls,pre_fn", ALL_CONFIGS, ids=ALL_ADAPTER_IDS)
    async def test_resolver_determines_principal(self, name, cls, pre_fn):
        @precondition("*")
        def require_admin(envelope):
            if envelope.principal is None or envelope.principal.role != "admin":
                return Verdict.fail("admin required")
            return Verdict.pass_()

        def resolver(tool_name: str, tool_input: dict) -> Principal:
            return Principal(role="admin")

        guard = _make_guard(contracts=[require_admin])
        adapter = cls(guard, principal_resolver=resolver)

        result = await pre_fn(adapter)
        assert not _is_denied(result), f"{name} denied when resolver returns admin"

    @pytest.mark.parametrize("name,cls,pre_fn", ALL_CONFIGS, ids=ALL_ADAPTER_IDS)
    async def test_resolver_overrides_static_principal(self, name, cls, pre_fn):
        @precondition("*")
        def require_admin(envelope):
            if envelope.principal is None or envelope.principal.role != "admin":
                return Verdict.fail("admin required")
            return Verdict.pass_()

        def resolver(tool_name: str, tool_input: dict) -> Principal:
            return Principal(role="admin")

        guard = _make_guard(contracts=[require_admin])
        # Static principal is viewer, but resolver returns admin
        adapter = cls(guard, principal=Principal(role="viewer"), principal_resolver=resolver)

        result = await pre_fn(adapter)
        assert not _is_denied(result), f"{name} denied when resolver returns admin (should override static viewer)"

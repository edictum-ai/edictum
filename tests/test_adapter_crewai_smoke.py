"""Real-framework CrewAI smokes (spec 01 §3 / L1.1 PR-1).

Drives a canary tool through CrewAI's own executor
(``execute_tool_and_check_finality``), not ``guard.run()`` and not a
direct call of ``adapter._before_hook``. Only the LLM is absent — the
action text is the ReAct payload the executor would parse from one.

Floor = crewai 1.5.0; latest = crewai 1.15.16 (edictum-schemas#26 @ 6ddd631).
Missing CrewAI is RED: this file claims the host.
Default/parity collection ignores this file (addopts + collect_ignore).
Dedicated smoke jobs set EDICTUM_CREWAI_SMOKE=1 and must stay fail-closed.
"""

from __future__ import annotations

import inspect

import crewai  # noqa: F401 — claimed host; ImportError is RED
import pytest
from crewai.agents.parser import AgentAction
from crewai.hooks.tool_hooks import clear_all_tool_call_hooks
from crewai.tools.structured_tool import CrewStructuredTool
from crewai.utilities.tool_utils import execute_tool_and_check_finality

from edictum import Decision, Edictum, precondition
from edictum.adapters.crewai import ADAPTER_INTERNAL_EXCEPTION_REASON, CrewAIAdapter
from edictum.approval import ApprovalDecision, ApprovalRequest, ApprovalStatus
from edictum.audit import AuditAction
from edictum.storage import MemoryBackend
from tests.conftest import NullAuditSink

_ASK_RULES = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: crewai-smoke-ask
defaults:
  mode: observe
tools:
  canary:
    side_effect: write
rules:
  - id: ask-canary
    type: pre
    tool: canary
    when:
      args.payload: {equals: ping}
    then:
      action: ask
      message: would ask a human
      timeout: 30
      timeout_action: block
"""


@precondition("canary")
def _block_canary(tool_call):
    return Decision.fail("canary blocked")


@precondition("other_tool")
def _block_other(tool_call):
    return Decision.fail("not the canary")


def _crewai_version() -> str:
    return getattr(crewai, "__version__", "unknown")


def _clear_hooks() -> None:
    clear_all_tool_call_hooks()


def _make_canary() -> tuple[CrewStructuredTool, dict[str, bool]]:
    flag = {"flipped": False}

    def canary(payload: str = "ping") -> str:
        """Flip the canary flag. Sentinel that the tool body ran."""
        flag["flipped"] = True
        return "flipped"

    tool = CrewStructuredTool.from_function(canary, name="canary")
    return tool, flag


def _drive(tool: CrewStructuredTool, tool_name: str = "canary"):
    """Invoke CrewAI's own tool-execution path (the seam that fires before-hooks)."""
    text = f'Thought: flip the canary\nAction: {tool_name}\nAction Input: {{"payload": "ping"}}'
    action = AgentAction(
        thought="flip the canary",
        tool=tool_name,
        tool_input='{"payload": "ping"}',
        text=text,
    )
    kwargs: dict = {"agent_action": action, "tools": [tool]}
    sig = inspect.signature(execute_tool_and_check_finality)
    if "i18n" in sig.parameters:
        from crewai.utilities.i18n import I18N

        kwargs["i18n"] = I18N()
    return execute_tool_and_check_finality(**kwargs)


def _result_text(result) -> str:
    return str(getattr(result, "result", result))


class SpyApprovalBackend:
    def __init__(self) -> None:
        self.requests: list[dict] = []

    async def request_approval(self, **kwargs):
        self.requests.append(kwargs)
        return ApprovalRequest(
            approval_id="spy-1",
            tool_name=kwargs.get("tool_name", ""),
            tool_args=kwargs.get("tool_args") or {},
            message=kwargs.get("message") or "",
            timeout=kwargs.get("timeout") or 30,
        )

    async def wait_for_decision(self, approval_id: str, timeout: int | None = None):
        return ApprovalDecision(approved=False, reason="spy-deny", status=ApprovalStatus.DENIED)


@pytest.fixture(autouse=True)
def _isolate_hooks():
    _clear_hooks()
    yield
    _clear_hooks()


def test_blocked_call_does_not_flip_canary():
    """Sentence: a blocked call does not execute. Flag stays down."""
    sink = NullAuditSink()
    guard = Edictum(environment="test", rules=[_block_canary], backend=MemoryBackend(), audit_sink=sink)
    adapter = CrewAIAdapter(guard, session_id="smoke-block")
    adapter.register()
    tool, flag = _make_canary()

    result = _drive(tool)

    assert flag["flipped"] is False, f"canary ran under a block rule (crewai {_crewai_version()})"
    text = _result_text(result).lower()
    assert "blocked by hook" in text, f"framework did not surface a block: {text!r}"
    denied = [e for e in sink.events if e.action == AuditAction.CALL_DENIED]
    assert denied, f"audit missing CALL_DENIED; got {[e.action for e in sink.events]}"
    assert any("canary blocked" in (e.reason or "") for e in denied)


def test_allowed_call_does_flip_canary():
    """Control: no-match allow path must actually execute the tool."""
    sink = NullAuditSink()
    guard = Edictum(environment="test", rules=[_block_other], backend=MemoryBackend(), audit_sink=sink)
    adapter = CrewAIAdapter(guard, session_id="smoke-allow")
    adapter.register()
    tool, flag = _make_canary()

    result = _drive(tool)

    assert flag["flipped"] is True, (
        f"control did not flip the flag (crewai {_crewai_version()}); result={_result_text(result)!r}"
    )
    allowed = [e for e in sink.events if e.action == AuditAction.CALL_ALLOWED]
    assert allowed, f"audit missing CALL_ALLOWED; got {[e.action for e in sink.events]}"


def test_enforce_exception_fails_closed():
    """D7: enforce + internal exception → block + fixed reason + audit; flag stays down."""
    sink = NullAuditSink()
    guard = Edictum(environment="test", rules=[_block_other], backend=MemoryBackend(), audit_sink=sink)
    adapter = CrewAIAdapter(guard, session_id="smoke-enforce-exc")
    adapter.register()

    async def explode(context):
        raise RuntimeError("backend outage")

    adapter._before_hook = explode
    tool, flag = _make_canary()

    result = _drive(tool)

    assert flag["flipped"] is False
    text = _result_text(result).lower()
    assert "blocked by hook" in text, f"enforce exception did not surface a block: {text!r}"
    events = [e for e in sink.events if e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON]
    assert events, f"missing loud exception audit; got {[(e.action, e.reason) for e in sink.events]}"
    assert events[0].action == AuditAction.CALL_DENIED
    assert events[0].decision_source == "adapter"
    assert events[0].policy_error is True
    assert adapter._internal_exception_count == 1


def test_observe_exception_allows_loudly():
    """D7: observe + internal exception → allow + own reason code; flag flips."""
    sink = NullAuditSink()
    guard = Edictum(environment="test", mode="observe", rules=[_block_other], backend=MemoryBackend(), audit_sink=sink)
    adapter = CrewAIAdapter(guard, session_id="smoke-observe-exc")
    adapter.register()

    async def explode(context):
        raise RuntimeError("backend outage")

    adapter._before_hook = explode
    tool, flag = _make_canary()

    result = _drive(tool)

    assert flag["flipped"] is True, (
        f"observe exception must allow; flag stayed down (crewai {_crewai_version()}); result={_result_text(result)!r}"
    )
    events = [e for e in sink.events if e.reason == ADAPTER_INTERNAL_EXCEPTION_REASON]
    assert events, f"missing loud observe-exception audit; got {[(e.action, e.reason) for e in sink.events]}"
    assert events[0].action == AuditAction.CALL_WOULD_DENY
    assert events[0].decision_source == "adapter"
    assert events[0].policy_error is True
    assert adapter._internal_exception_count == 1


def test_observe_ask_does_not_ping_approval_backend():
    """D7: observe + action:ask must not call ApprovalBackend and must not block."""
    sink = NullAuditSink()
    spy = SpyApprovalBackend()
    guard = Edictum.from_yaml_string(
        _ASK_RULES,
        mode="observe",
        backend=MemoryBackend(),
        audit_sink=sink,
        approval_backend=spy,
    )
    adapter = CrewAIAdapter(guard, session_id="smoke-observe-ask")
    adapter.register()
    tool, flag = _make_canary()

    result = _drive(tool)

    assert spy.requests == [], f"observe+ask pinged ApprovalBackend: {spy.requests}"
    assert flag["flipped"] is True, f"observe+ask must not deny; flag stayed down; result={_result_text(result)!r}"
    would = [e for e in sink.events if e.action == AuditAction.CALL_WOULD_DENY]
    assert would, f"observe+ask missing CALL_WOULD_DENY; got {[e.action for e in sink.events]}"

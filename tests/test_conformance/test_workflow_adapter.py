"""Conformance runner for shared workflow adapter fixtures from edictum-schemas."""

from __future__ import annotations

import os
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from edictum import Edictum
from edictum.adapters.crewai import CrewAIAdapter
from edictum.adapters.google_adk import GoogleADKAdapter
from edictum.adapters.langchain import LangChainAdapter
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from edictum.approval import ApprovalDecision, ApprovalRequest, ApprovalStatus
from edictum.session import Session, validate_session_id
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowEvidence, WorkflowState
from edictum.workflow.state import save_state

_BUNDLE = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: workflow-adapter-conformance
defaults:
  mode: enforce
rules:
  - id: noop-pre
    type: pre
    tool: Noop
    when:
      args.path:
        equals: never
    then:
      action: block
      message: never
"""

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFORMANCE_REQUIRED = os.environ.get("EDICTUM_CONFORMANCE_REQUIRED") == "1"
_ACTION_ALIASES = {
    "call_denied": "call_blocked",
    "call_approval_denied": "call_approval_blocked",
    "call_approval_requested": "call_asked",
}


def _resolve_env_path(value: str) -> list[Path]:
    path = Path(value)
    if path.is_absolute():
        return [path]
    return [path, Path.cwd() / path, _REPO_ROOT / path]


def _find_workflow_adapter_dir() -> Path | None:
    candidates: list[Path] = []

    fixtures_env = os.environ.get("EDICTUM_FIXTURES_DIR")
    if fixtures_env:
        for path in _resolve_env_path(fixtures_env):
            candidates.append(path / "workflow-adapter-conformance")

    schemas_env = os.environ.get("EDICTUM_SCHEMAS_DIR")
    if schemas_env:
        for path in _resolve_env_path(schemas_env):
            candidates.append(path / "fixtures" / "workflow-adapter-conformance")

    candidates.append(_REPO_ROOT / "edictum-schemas" / "fixtures" / "workflow-adapter-conformance")
    candidates.append(_REPO_ROOT.parent / "edictum-schemas" / "fixtures" / "workflow-adapter-conformance")

    for candidate in candidates:
        if candidate.is_dir() and any(candidate.glob("*.workflow-adapter.yaml")):
            return candidate

    for root in (Path.cwd(), _REPO_ROOT, _REPO_ROOT.parent):
        for fixture in root.glob("**/workflow-adapter-conformance/*.workflow-adapter.yaml"):
            return fixture.parent
    return None


WORKFLOW_ADAPTER_DIR = _find_workflow_adapter_dir()


def _suite_cases() -> list[Any]:
    if WORKFLOW_ADAPTER_DIR is None:
        return []

    params: list[Any] = []
    for path in sorted(WORKFLOW_ADAPTER_DIR.glob("*.workflow-adapter.yaml")):
        suite = yaml.safe_load(path.read_text())
        suite_name = suite.get("suite", path.stem)
        for fixture in suite.get("fixtures", []):
            params.append(pytest.param(suite, fixture, id=f"{suite_name}/{fixture['id']}"))
    return params


_FIXTURE_PARAMS = _suite_cases()

if _CONFORMANCE_REQUIRED and not _FIXTURE_PARAMS:
    raise FileNotFoundError(
        "EDICTUM_CONFORMANCE_REQUIRED=1 but workflow adapter fixtures were not found. "
        "Set EDICTUM_SCHEMAS_DIR or ensure edictum-schemas is checked out."
    )

pytestmark = pytest.mark.skipif(
    not _FIXTURE_PARAMS,
    reason="edictum-schemas not found (set EDICTUM_SCHEMAS_DIR)",
)


class ScriptedApprovalBackend:
    def __init__(self) -> None:
        self._outcomes: deque[str] = deque()
        self._request_count = 0

    def queue(self, outcomes: list[str]) -> None:
        self._outcomes = deque(outcomes)

    async def request_approval(
        self,
        tool_name: str,
        tool_args: dict,
        message: str,
        *,
        timeout: int = 300,
        timeout_action: str = "block",
        principal: dict | None = None,
        metadata: dict | None = None,
        session_id: str | None = None,
    ) -> ApprovalRequest:
        self._request_count += 1
        return ApprovalRequest(
            approval_id=f"approval-{self._request_count}",
            tool_name=tool_name,
            tool_args=tool_args,
            message=message,
            timeout=timeout,
            timeout_action=timeout_action,
            principal=principal,
            metadata=metadata or {},
            session_id=session_id,
        )

    async def wait_for_decision(self, approval_id: str, timeout: int | None = None) -> ApprovalDecision:
        if not self._outcomes:
            raise AssertionError(f"missing approval outcome for {approval_id}")

        outcome = self._outcomes.popleft()
        if outcome == "approved":
            return ApprovalDecision(approved=True, approver="tests", status=ApprovalStatus.APPROVED)
        if outcome == "rejected":
            return ApprovalDecision(
                approved=False,
                approver="tests",
                reason="blocked in conformance test",
                status=ApprovalStatus.DENIED,
            )
        raise AssertionError(f"unsupported approval outcome: {outcome}")


@dataclass(frozen=True)
class AdapterHarness:
    name: str
    build: Callable[[Edictum, str, str | None], Any]
    pre: Callable[[Any, str, dict[str, Any], str], Awaitable[Any]]
    post: Callable[[Any, str, dict[str, Any], str, str], Awaitable[None]]
    is_blocked: Callable[[Any], bool]


def _build_langchain(guard: Edictum, session_id: str, parent_session_id: str | None) -> LangChainAdapter:
    adapter = LangChainAdapter(guard, session_id=session_id)
    _set_parent_session_id(adapter, parent_session_id)
    return adapter


async def _pre_langchain(adapter: LangChainAdapter, tool: str, args: dict[str, Any], call_id: str) -> Any:
    request = SimpleNamespace(tool_call={"name": tool, "args": args, "id": call_id})
    return await adapter._pre_tool_call(request)


async def _post_langchain(
    adapter: LangChainAdapter,
    tool: str,
    args: dict[str, Any],
    call_id: str,
    execution: str,
) -> None:
    request = SimpleNamespace(tool_call={"name": tool, "args": args, "id": call_id})
    await adapter._post_tool_call(request, _tool_result(tool, execution))


def _build_crewai(guard: Edictum, session_id: str, parent_session_id: str | None) -> CrewAIAdapter:
    adapter = CrewAIAdapter(guard, session_id=session_id)
    _set_parent_session_id(adapter, parent_session_id)
    return adapter


async def _pre_crewai(adapter: CrewAIAdapter, tool: str, args: dict[str, Any], call_id: str) -> Any:
    return await adapter._before_hook(SimpleNamespace(tool_name=tool, tool_input=args))


async def _post_crewai(
    adapter: CrewAIAdapter,
    tool: str,
    args: dict[str, Any],
    call_id: str,
    execution: str,
) -> None:
    await adapter._after_hook(
        SimpleNamespace(
            tool_name=tool,
            tool_input=args,
            tool_result=_tool_result(tool, execution),
        )
    )


def _build_openai(guard: Edictum, session_id: str, parent_session_id: str | None) -> OpenAIAgentsAdapter:
    adapter = OpenAIAgentsAdapter(guard, session_id=session_id)
    _set_parent_session_id(adapter, parent_session_id)
    return adapter


async def _pre_openai(adapter: OpenAIAgentsAdapter, tool: str, args: dict[str, Any], call_id: str) -> Any:
    return await adapter._pre(tool, args, call_id)


async def _post_openai(
    adapter: OpenAIAgentsAdapter,
    tool: str,
    args: dict[str, Any],
    call_id: str,
    execution: str,
) -> None:
    await adapter._post(call_id, _tool_result(tool, execution))


def _build_google(guard: Edictum, session_id: str, parent_session_id: str | None) -> GoogleADKAdapter:
    adapter = GoogleADKAdapter(guard, session_id=session_id)
    _set_parent_session_id(adapter, parent_session_id)
    return adapter


async def _pre_google(adapter: GoogleADKAdapter, tool: str, args: dict[str, Any], call_id: str) -> Any:
    return await adapter._pre(tool, args, call_id)


async def _post_google(
    adapter: GoogleADKAdapter,
    tool: str,
    args: dict[str, Any],
    call_id: str,
    execution: str,
) -> None:
    await adapter._post(call_id, _tool_result(tool, execution))


def _is_blocked_string(result: Any) -> bool:
    return isinstance(result, str) and "DENIED" in result


def _is_blocked_langchain(result: Any) -> bool:
    if isinstance(result, str):
        return "DENIED" in result
    return "DENIED" in str(getattr(result, "content", ""))


def _is_blocked_dict(result: Any) -> bool:
    return isinstance(result, dict) and "DENIED" in str(result.get("error", ""))


def _set_parent_session_id(adapter: Any, value: str | None) -> None:
    if value is None:
        adapter._parent_session_id = None
        return
    validate_session_id(value)
    adapter._parent_session_id = value


ADAPTERS = [
    AdapterHarness("CrewAI", _build_crewai, _pre_crewai, _post_crewai, _is_blocked_string),
    AdapterHarness("GoogleADK", _build_google, _pre_google, _post_google, _is_blocked_dict),
    AdapterHarness("LangChain", _build_langchain, _pre_langchain, _post_langchain, _is_blocked_langchain),
    AdapterHarness("OpenAI", _build_openai, _pre_openai, _post_openai, _is_blocked_string),
]


def _tool_result(tool: str, execution: str) -> str:
    if execution == "error":
        return f"Error: {tool} failed"
    if tool == "Read":
        return "spec"
    return "ok"


def _seed_state_payload(initial: dict[str, Any]) -> WorkflowState:
    state = WorkflowState(
        session_id=initial["session_id"],
        active_stage=initial["active_stage"],
        completed_stages=list(initial["completed_stages"]),
        approvals=dict(initial["approvals"]),
        evidence=WorkflowEvidence(
            reads=list(initial["evidence"]["reads"]),
            stage_calls={key: list(value) for key, value in initial["evidence"]["stage_calls"].items()},
        ),
        blocked_reason=initial.get("blocked_reason"),
        pending_approval=dict(initial.get("pending_approval", {"required": False})),
        last_blocked_action=initial.get("last_blocked_action"),
        last_recorded_evidence=initial.get("last_recorded_evidence"),
    )
    state.ensure_defaults()
    return state


def _canonical_action(action: Any) -> str:
    value = getattr(action, "value", action)
    return _ACTION_ALIASES.get(str(value), str(value))


def _decision_from_result(result: Any, harness: AdapterHarness) -> str:
    if result is None:
        return "allow"
    if harness.is_blocked(result):
        return "block"
    return "pause"


def _assert_partial(actual: Any, expected: Any, label: str) -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict), f"{label}: expected dict, got {type(actual).__name__}"
        for key, value in expected.items():
            assert key in actual, f"{label}: missing key {key!r}"
            _assert_partial(actual[key], value, f"{label}.{key}")
        return
    assert actual == expected, f"{label}: expected {expected!r}, got {actual!r}"


def _event_payload(event: Any) -> dict[str, Any]:
    payload = {
        "action": _canonical_action(event.action),
        "session_id": event.session_id,
        "parent_session_id": event.parent_session_id,
    }
    if event.workflow is not None:
        payload["workflow"] = event.workflow
    return payload


@pytest.mark.asyncio
@pytest.mark.parametrize("adapter", ADAPTERS, ids=[adapter.name for adapter in ADAPTERS])
@pytest.mark.parametrize("suite,fixture", _FIXTURE_PARAMS)
async def test_workflow_adapter_conformance(
    adapter: AdapterHarness,
    suite: dict[str, Any],
    fixture: dict[str, Any],
) -> None:
    backend = MemoryBackend()
    approvals = ScriptedApprovalBackend()
    workflow_content = yaml.safe_dump(suite["workflows"][fixture["workflow"]], sort_keys=False)
    guard = Edictum.from_yaml_string(
        _BUNDLE,
        backend=backend,
        workflow_content=workflow_content,
        approval_backend=approvals,
    )
    runtime = guard._workflow_runtime
    assert runtime is not None

    session_id = fixture["initial_state"]["session_id"]
    parent_session_id = fixture.get("lineage", {}).get("parent_session_id")
    session = Session(session_id, backend)
    await save_state(session, runtime.definition, _seed_state_payload(fixture["initial_state"]))

    instance = adapter.build(guard, session_id, parent_session_id)

    for step in fixture["steps"]:
        approvals.queue(list(step.get("approval_outcomes", [])))
        mark = guard.local_sink.mark()
        call_id = f"{fixture['id']}-{step['id']}"
        call = step["call"]
        pre_result = await adapter.pre(instance, call["tool"], dict(call["args"]), call_id)

        if step["execution"] != "not_run" and _decision_from_result(pre_result, adapter) == "allow":
            await adapter.post(instance, call["tool"], dict(call["args"]), call_id, step["execution"])

        expect = step["expect"]
        assert _decision_from_result(pre_result, adapter) == expect["decision"], step["id"]

        state = await runtime.state(session)
        assert state.active_stage == expect["active_stage"], step["id"]
        assert state.completed_stages == expect["completed_stages"], step["id"]
        assert state.approvals == expect["approvals"], step["id"]
        assert state.evidence.reads == expect["evidence"]["reads"], step["id"]
        assert state.evidence.stage_calls == expect["evidence"]["stage_calls"], step["id"]
        assert state.blocked_reason == expect["blocked_reason"], step["id"]
        assert state.pending_approval == expect["pending_approval"], step["id"]

        actual_events = [_event_payload(event) for event in guard.local_sink.since_mark(mark)]
        expected_events = expect["audit_events"]
        assert len(actual_events) == len(expected_events), step["id"]
        for index, expected_event in enumerate(expected_events):
            _assert_partial(actual_events[index], expected_event, f"{step['id']}.audit_events[{index}]")

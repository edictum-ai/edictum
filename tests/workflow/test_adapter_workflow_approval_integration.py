from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Edictum
from edictum.adapters.agno import AgnoAdapter
from edictum.adapters.claude_agent_sdk import ClaudeAgentSDKAdapter
from edictum.adapters.crewai import CrewAIAdapter
from edictum.adapters.google_adk import GoogleADKAdapter
from edictum.adapters.langchain import LangChainAdapter
from edictum.adapters.nanobot import GovernedToolRegistry
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from edictum.adapters.semantic_kernel import SemanticKernelAdapter
from edictum.audit import AuditAction
from edictum.session import Session
from edictum.storage import MemoryBackend

from .conftest import AutoApproveBackend

_BUNDLE = """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: adapter-bundle
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

_WORKFLOW = """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: adapter-approval-workflow
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: Read spec first
  - id: review
    entry:
      - condition: stage_complete("read-context")
    approval:
      message: approve before push
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
"""


def _build_guard() -> Edictum:
    return Edictum.from_yaml_string(
        _BUNDLE,
        backend=MemoryBackend(),
        workflow_content=_WORKFLOW,
        approval_backend=AutoApproveBackend(),
    )


async def _state(guard: Edictum, session_id: str):
    runtime = guard._workflow_runtime
    assert runtime is not None
    return await runtime.state(Session(session_id, guard.backend))


def _assert_last_recorded_evidence(guard: Edictum, session_id: str, tool: str, summary: str) -> None:
    events = [
        event
        for event in guard.local_sink.events
        if event.action == AuditAction.CALL_EXECUTED and event.session_id == session_id
    ]
    assert events
    workflow = events[-1].workflow
    assert workflow is not None
    evidence = workflow.get("last_recorded_evidence")
    assert evidence is not None
    assert evidence["tool"] == tool
    assert evidence["summary"] == summary


@pytest.mark.asyncio
async def test_langchain_adapter_workflow_approval_advances_and_completes():
    guard = _build_guard()
    adapter = LangChainAdapter(guard, session_id="langchain-approval")

    read_request = SimpleNamespace(tool_call={"name": "Read", "args": {"path": "spec.md"}, "id": "read-1"})
    push_request = SimpleNamespace(
        tool_call={"name": "Bash", "args": {"command": "git push origin branch"}, "id": "push-1"}
    )

    assert await adapter._pre_tool_call(read_request) is None
    await adapter._post_tool_call(read_request, "spec")

    assert await adapter._pre_tool_call(push_request) is None
    await adapter._post_tool_call(push_request, "ok")

    state = await _state(guard, "langchain-approval")
    assert state.active_stage == "push"
    assert state.completed_stages == ["read-context", "review"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]
    _assert_last_recorded_evidence(guard, "langchain-approval", "Bash", "git push origin branch")


@pytest.mark.asyncio
async def test_openai_adapter_workflow_approval_advances_and_completes():
    guard = _build_guard()
    adapter = OpenAIAgentsAdapter(guard, session_id="openai-approval")

    assert await adapter._pre("Read", {"path": "spec.md"}, "read-1") is None
    await adapter._post("read-1", "spec")

    assert await adapter._pre("Bash", {"command": "git push origin branch"}, "push-1") is None
    await adapter._post("push-1", "ok")

    state = await _state(guard, "openai-approval")
    assert state.active_stage == "push"
    assert state.completed_stages == ["read-context", "review"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]
    _assert_last_recorded_evidence(guard, "openai-approval", "Bash", "git push origin branch")


@pytest.mark.asyncio
async def test_crewai_adapter_workflow_approval_advances_and_completes():
    guard = _build_guard()
    adapter = CrewAIAdapter(guard, session_id="crewai-approval")

    read_context = SimpleNamespace(tool_name="Read", tool_input={"path": "spec.md"}, tool_result="spec")
    push_context = SimpleNamespace(
        tool_name="Bash",
        tool_input={"command": "git push origin branch"},
        tool_result="ok",
    )

    assert await adapter._before_hook(read_context) is None
    await adapter._after_hook(read_context)

    assert await adapter._before_hook(push_context) is None
    await adapter._after_hook(push_context)

    state = await _state(guard, "crewai-approval")
    assert state.active_stage == "push"
    assert state.completed_stages == ["read-context", "review"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]
    _assert_last_recorded_evidence(guard, "crewai-approval", "Bash", "git push origin branch")


@pytest.mark.asyncio
async def test_google_adapter_workflow_approval_advances_and_completes():
    guard = _build_guard()
    adapter = GoogleADKAdapter(guard, session_id="google-approval")

    assert await adapter._pre("Read", {"path": "spec.md"}, "read-1") is None
    await adapter._post("read-1", "spec")

    assert await adapter._pre("Bash", {"command": "git push origin branch"}, "push-1") is None
    await adapter._post("push-1", "ok")

    state = await _state(guard, "google-approval")
    assert state.active_stage == "push"
    assert state.completed_stages == ["read-context", "review"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]
    _assert_last_recorded_evidence(guard, "google-approval", "Bash", "git push origin branch")


@pytest.mark.asyncio
async def test_agno_adapter_workflow_approval_advances_and_completes():
    guard = _build_guard()
    adapter = AgnoAdapter(guard, session_id="agno-approval")

    assert await adapter._pre("Read", {"path": "spec.md"}, "read-1") == {}
    await adapter._post("read-1", "spec", tool_success=True)

    assert await adapter._pre("Bash", {"command": "git push origin branch"}, "push-1") == {}
    await adapter._post("push-1", "ok", tool_success=True)

    state = await _state(guard, "agno-approval")
    assert state.active_stage == "push"
    assert state.completed_stages == ["read-context", "review"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]
    _assert_last_recorded_evidence(guard, "agno-approval", "Bash", "git push origin branch")


@pytest.mark.asyncio
async def test_claude_adapter_workflow_approval_advances_and_completes():
    guard = _build_guard()
    adapter = ClaudeAgentSDKAdapter(guard, session_id="claude-approval")

    assert await adapter._pre_tool_use("Read", {"path": "spec.md"}, "read-1") == {}
    assert await adapter._post_tool_use("read-1", "spec") == {}

    assert await adapter._pre_tool_use("Bash", {"command": "git push origin branch"}, "push-1") == {}
    assert await adapter._post_tool_use("push-1", "ok") == {}

    state = await _state(guard, "claude-approval")
    assert state.active_stage == "push"
    assert state.completed_stages == ["read-context", "review"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]
    _assert_last_recorded_evidence(guard, "claude-approval", "Bash", "git push origin branch")


@pytest.mark.asyncio
async def test_semantic_kernel_adapter_workflow_approval_advances_and_completes():
    guard = _build_guard()
    adapter = SemanticKernelAdapter(guard, session_id="sk-approval")

    assert await adapter._pre("Read", {"path": "spec.md"}, "read-1") == {}
    await adapter._post("read-1", "spec")

    assert await adapter._pre("Bash", {"command": "git push origin branch"}, "push-1") == {}
    await adapter._post("push-1", "ok")

    state = await _state(guard, "sk-approval")
    assert state.active_stage == "push"
    assert state.completed_stages == ["read-context", "review"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]
    _assert_last_recorded_evidence(guard, "sk-approval", "Bash", "git push origin branch")


class _InnerRegistry:
    def register(self, name, handler, description=""):
        return None

    def list_tools(self):
        return ["Read", "Bash"]

    def get_description(self, name):
        return name

    async def execute(self, name, args):
        if name == "Read":
            return "spec"
        return "ok"


@pytest.mark.asyncio
async def test_nanobot_adapter_workflow_approval_advances_and_completes():
    guard = _build_guard()
    registry = GovernedToolRegistry(_InnerRegistry(), guard, session_id="nanobot-approval")

    assert await registry.execute("Read", {"path": "spec.md"}) == "spec"
    assert await registry.execute("Bash", {"command": "git push origin branch"}) == "ok"

    state = await _state(guard, "nanobot-approval")
    assert state.active_stage == "push"
    assert state.completed_stages == ["read-context", "review"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]
    _assert_last_recorded_evidence(guard, "nanobot-approval", "Bash", "git push origin branch")

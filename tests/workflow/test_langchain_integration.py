from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Edictum
from edictum.adapters.langchain import LangChainAdapter
from edictum.session import Session
from edictum.storage import MemoryBackend

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
  name: adapter-workflow
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: Read spec first
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
"""


async def _workflow_state(guard: Edictum, session_id: str):
    runtime = guard._workflow_runtime
    assert runtime is not None
    return await runtime.state(Session(session_id, guard.backend))


@pytest.mark.asyncio
async def test_langchain_adapter_workflow_progresses_after_successful_read():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = LangChainAdapter(guard, session_id="langchain-workflow")

    blocked_request = SimpleNamespace(tool_call={"name": "Edit", "args": {"path": "src/app.py"}, "id": "edit-1"})
    blocked = await adapter._pre_tool_call(blocked_request)
    assert blocked is not None

    read_request = SimpleNamespace(tool_call={"name": "Read", "args": {"path": "spec.md"}, "id": "read-1"})
    assert await adapter._pre_tool_call(read_request) is None
    await adapter._post_tool_call(read_request, "spec")

    allowed_request = SimpleNamespace(tool_call={"name": "Edit", "args": {"path": "src/app.py"}, "id": "edit-2"})
    allowed = await adapter._pre_tool_call(allowed_request)
    assert allowed is None


@pytest.mark.asyncio
async def test_langchain_adapter_records_read_evidence_only_after_success():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = LangChainAdapter(guard, session_id="langchain-workflow-failure")

    failed_read = SimpleNamespace(tool_call={"name": "Read", "args": {"path": "spec.md"}, "id": "read-1"})
    assert await adapter._pre_tool_call(failed_read) is None
    await adapter._post_tool_call(failed_read, "Error: read failed")

    state = await _workflow_state(guard, "langchain-workflow-failure")
    assert state.evidence.reads == []

    blocked_request = SimpleNamespace(tool_call={"name": "Edit", "args": {"path": "src/app.py"}, "id": "edit-1"})
    blocked = await adapter._pre_tool_call(blocked_request)
    assert blocked is not None

    successful_read = SimpleNamespace(tool_call={"name": "Read", "args": {"path": "spec.md"}, "id": "read-2"})
    assert await adapter._pre_tool_call(successful_read) is None
    await adapter._post_tool_call(successful_read, "spec")

    state = await _workflow_state(guard, "langchain-workflow-failure")
    assert state.evidence.reads == ["spec.md"]

    allowed_request = SimpleNamespace(tool_call={"name": "Edit", "args": {"path": "src/app.py"}, "id": "edit-2"})
    allowed = await adapter._pre_tool_call(allowed_request)
    assert allowed is None

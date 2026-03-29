from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Edictum
from edictum.adapters.langchain import LangChainAdapter
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


@pytest.mark.asyncio
async def test_langchain_adapter_workflow_progresses_after_successful_read():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = LangChainAdapter(guard, session_id="langchain-workflow")

    denied_request = SimpleNamespace(tool_call={"name": "Edit", "args": {"path": "src/app.py"}, "id": "edit-1"})
    denied = await adapter._pre_tool_call(denied_request)
    assert denied is not None

    read_request = SimpleNamespace(tool_call={"name": "Read", "args": {"path": "spec.md"}, "id": "read-1"})
    assert await adapter._pre_tool_call(read_request) is None
    await adapter._post_tool_call(read_request, "spec")

    allowed_request = SimpleNamespace(tool_call={"name": "Edit", "args": {"path": "src/app.py"}, "id": "edit-2"})
    allowed = await adapter._pre_tool_call(allowed_request)
    assert allowed is None

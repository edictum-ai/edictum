from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Edictum
from edictum.adapters.crewai import CrewAIAdapter
from edictum.storage import MemoryBackend

from .test_langchain_integration import _BUNDLE, _WORKFLOW, _workflow_state


@pytest.mark.asyncio
async def test_crewai_adapter_workflow_progresses_after_successful_read():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = CrewAIAdapter(guard, session_id="crewai-workflow")

    blocked = await adapter._before_hook(SimpleNamespace(tool_name="Edit", tool_input={"path": "src/app.py"}))
    assert blocked is not None

    read_context = SimpleNamespace(tool_name="Read", tool_input={"path": "spec.md"}, tool_result="spec")
    assert await adapter._before_hook(read_context) is None
    await adapter._after_hook(read_context)

    allowed = await adapter._before_hook(SimpleNamespace(tool_name="Edit", tool_input={"path": "src/app.py"}))
    assert allowed is None


@pytest.mark.asyncio
async def test_crewai_adapter_records_read_evidence_only_after_success():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = CrewAIAdapter(guard, session_id="crewai-workflow-failure")

    failed_read = SimpleNamespace(tool_name="Read", tool_input={"path": "spec.md"}, tool_result="Error: read failed")
    assert await adapter._before_hook(failed_read) is None
    await adapter._after_hook(failed_read)

    state = await _workflow_state(guard, "crewai-workflow-failure")
    assert state.evidence.reads == []

    blocked = await adapter._before_hook(SimpleNamespace(tool_name="Edit", tool_input={"path": "src/app.py"}))
    assert blocked is not None

    successful_read = SimpleNamespace(tool_name="Read", tool_input={"path": "spec.md"}, tool_result="spec")
    assert await adapter._before_hook(successful_read) is None
    await adapter._after_hook(successful_read)

    state = await _workflow_state(guard, "crewai-workflow-failure")
    assert state.evidence.reads == ["spec.md"]

    allowed = await adapter._before_hook(SimpleNamespace(tool_name="Edit", tool_input={"path": "src/app.py"}))
    assert allowed is None

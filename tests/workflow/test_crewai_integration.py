from __future__ import annotations

from types import SimpleNamespace

import pytest

from edictum import Edictum
from edictum.adapters.crewai import CrewAIAdapter
from edictum.storage import MemoryBackend

from .test_langchain_integration import _BUNDLE, _WORKFLOW


@pytest.mark.asyncio
async def test_crewai_adapter_workflow_progresses_after_successful_read():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = CrewAIAdapter(guard, session_id="crewai-workflow")

    denied = await adapter._before_hook(SimpleNamespace(tool_name="Edit", tool_input={"path": "src/app.py"}))
    assert denied is not None

    read_context = SimpleNamespace(tool_name="Read", tool_input={"path": "spec.md"}, tool_result="spec")
    assert await adapter._before_hook(read_context) is None
    await adapter._after_hook(read_context)

    allowed = await adapter._before_hook(SimpleNamespace(tool_name="Edit", tool_input={"path": "src/app.py"}))
    assert allowed is None

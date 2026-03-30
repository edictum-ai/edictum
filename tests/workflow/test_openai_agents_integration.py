from __future__ import annotations

import pytest

from edictum import Edictum
from edictum.adapters.openai_agents import OpenAIAgentsAdapter
from edictum.storage import MemoryBackend

from .test_langchain_integration import _BUNDLE, _WORKFLOW


@pytest.mark.asyncio
async def test_openai_agents_adapter_workflow_progresses_after_successful_read():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = OpenAIAgentsAdapter(guard, session_id="openai-workflow")

    denied = await adapter._pre("Edit", {"path": "src/app.py"}, "edit-1")
    assert denied is not None

    assert await adapter._pre("Read", {"path": "spec.md"}, "read-1") is None
    await adapter._post("read-1", "spec")

    allowed = await adapter._pre("Edit", {"path": "src/app.py"}, "edit-2")
    assert allowed is None

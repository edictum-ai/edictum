from __future__ import annotations

import pytest

from edictum import Edictum
from edictum.adapters.google_adk import GoogleADKAdapter
from edictum.storage import MemoryBackend

from .test_langchain_integration import _BUNDLE, _WORKFLOW, _workflow_state


@pytest.mark.asyncio
async def test_google_adk_adapter_workflow_progresses_after_successful_read():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = GoogleADKAdapter(guard, session_id="google-workflow")

    blocked = await adapter._pre("Edit", {"path": "src/app.py"}, "edit-1")
    assert blocked is not None

    assert await adapter._pre("Read", {"path": "spec.md"}, "read-1") is None
    await adapter._post("read-1", "spec")

    allowed = await adapter._pre("Edit", {"path": "src/app.py"}, "edit-2")
    assert allowed is None


@pytest.mark.asyncio
async def test_google_adk_adapter_records_read_evidence_only_after_success():
    guard = Edictum.from_yaml_string(_BUNDLE, backend=MemoryBackend(), workflow_content=_WORKFLOW)
    adapter = GoogleADKAdapter(guard, session_id="google-workflow-failure")

    assert await adapter._pre("Read", {"path": "spec.md"}, "read-1") is None
    await adapter._post("read-1", "Error: read failed")

    state = await _workflow_state(guard, "google-workflow-failure")
    assert state.evidence.reads == []

    blocked = await adapter._pre("Edit", {"path": "src/app.py"}, "edit-1")
    assert blocked is not None

    assert await adapter._pre("Read", {"path": "spec.md"}, "read-2") is None
    await adapter._post("read-2", "spec")

    state = await _workflow_state(guard, "google-workflow-failure")
    assert state.evidence.reads == ["spec.md"]

    allowed = await adapter._pre("Edit", {"path": "src/app.py"}, "edit-2")
    assert allowed is None

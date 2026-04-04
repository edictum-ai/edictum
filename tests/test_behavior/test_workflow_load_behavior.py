from __future__ import annotations

import json

import pytest

from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowMetadata
from tests.workflow.conftest import make_envelope, make_runtime


def test_workflow_metadata_second_positional_arg_sets_description():
    metadata = WorkflowMetadata("behavior-workflow-position", "workflow description")

    assert metadata.description == "workflow description"
    assert metadata.version == ""


@pytest.mark.asyncio
@pytest.mark.security
async def test_runtime_state_drops_invalid_persisted_last_recorded_evidence():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-workflow-invalid-evidence
stages:
  - id: implement
    tools: [Read]
"""
    )
    session = Session("behavior-workflow-invalid-evidence", MemoryBackend())
    await session.set_value(
        "workflow:behavior-workflow-invalid-evidence:state",
        json.dumps(
            {
                "active_stage": "implement",
                "last_recorded_evidence": {
                    "tool": "Read",
                    "summary": "x" * 4097,
                    "timestamp": "2026-04-04T00:00:00Z",
                    "extra": {"nested": "value"},
                },
            }
        ),
    )

    state = await runtime.state(session)

    assert state.last_recorded_evidence is None


@pytest.mark.asyncio
async def test_workflow_metadata_version_changes_audit_snapshot():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-workflow-version
  version: "2026-04-04"
stages:
  - id: implement
    tools: [Edit]
"""
    )
    session = Session("behavior-workflow-version", MemoryBackend())

    decision = await runtime.evaluate(session, make_envelope("Edit", {"path": "src/app.py"}))

    assert decision.audit is not None
    assert decision.audit["version"] == "2026-04-04"

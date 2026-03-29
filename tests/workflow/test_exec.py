from __future__ import annotations

import pytest

from edictum.envelope import create_envelope
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowRuntime, load_workflow_string

EXEC_WORKFLOW = """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: exec-verify
stages:
  - id: verify
    tools: [Bash]
    exit:
      - condition: exec("python3 -c \\"raise SystemExit(0)\\"", exit_code=0)
        message: command must pass
"""


def test_exec_evaluator_requires_opt_in():
    with pytest.raises(ValueError, match="exec\\(\\.\\.\\.\\) conditions require exec_evaluator_enabled=True"):
        WorkflowRuntime(load_workflow_string(EXEC_WORKFLOW))


@pytest.mark.asyncio
async def test_exec_evaluator_runs_when_enabled():
    runtime = WorkflowRuntime(load_workflow_string(EXEC_WORKFLOW), exec_evaluator_enabled=True)
    session = Session("exec-session", MemoryBackend())

    decision = await runtime.evaluate(session, create_envelope("Bash", {"command": "python3 -V"}))

    assert decision.action == "allow"
    await runtime.record_result(session, decision.stage_id, create_envelope("Bash", {"command": "python3 -V"}))
    state = await runtime.state(session)
    assert state.active_stage == ""

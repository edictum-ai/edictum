from __future__ import annotations

import json

import pytest

from edictum.envelope import create_envelope
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowRuntime, load_workflow_string

_APPROVAL_WORKFLOW = """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: approval-bypass-test
stages:
  - id: review
    approval:
      message: Human approval required
  - id: execute
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
"""

_CHECK_WORKFLOW = """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: command-check-security
stages:
  - id: execute
    tools: [Bash]
    checks:
      - command_matches: "^git push origin main$"
        message: only the release push is allowed
"""


@pytest.mark.security
@pytest.mark.asyncio
async def test_forged_approval_state_is_observable_in_workflow_evaluation():
    """Forged approval state is observable, documenting the storage trust boundary."""
    runtime = WorkflowRuntime(load_workflow_string(_APPROVAL_WORKFLOW))
    session = Session("forged-approval", MemoryBackend())
    forged = json.dumps(
        {
            "session_id": session.session_id,
            "active_stage": "review",
            "completed_stages": [],
            "approvals": {"review": "approved"},
            "evidence": {"reads": [], "stage_calls": {}},
        }
    )
    await session.set_value("workflow:approval-bypass-test:state", forged)

    decision = await runtime.evaluate(
        session,
        create_envelope("Bash", {"command": "git push origin main"}),
    )

    assert decision.action == "allow"
    assert decision.stage_id == "execute"


@pytest.mark.security
@pytest.mark.asyncio
async def test_forged_completed_state_is_observable_in_workflow_evaluation():
    """Forged completed state is observable, documenting the storage trust boundary."""
    runtime = WorkflowRuntime(load_workflow_string(_APPROVAL_WORKFLOW))
    session = Session("forged-complete", MemoryBackend())
    forged = json.dumps(
        {
            "session_id": session.session_id,
            "active_stage": "",
            "completed_stages": ["review", "execute"],
            "approvals": {},
            "evidence": {"reads": [], "stage_calls": {}},
        }
    )
    await session.set_value("workflow:approval-bypass-test:state", forged)

    decision = await runtime.evaluate(
        session,
        create_envelope("Bash", {"command": "git push origin main"}),
    )

    assert decision.action == "allow"
    assert decision.stage_id == ""


@pytest.mark.security
@pytest.mark.asyncio
async def test_command_matches_newline_payload_is_blocked():
    """A newline-padded Bash command must not slip past command_matches checks."""
    runtime = WorkflowRuntime(load_workflow_string(_CHECK_WORKFLOW))
    session = Session("command-check", MemoryBackend())

    decision = await runtime.evaluate(
        session,
        create_envelope("Bash", {"command": "git push origin main\nrm -rf /"}),
    )

    assert decision.action == "block"
    assert "release push" in (decision.reason or "")

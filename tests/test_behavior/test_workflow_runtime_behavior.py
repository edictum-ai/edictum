"""Behavior tests for workflow runtime stage moves."""

from __future__ import annotations

import pytest

from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowEvidence, WorkflowState
from edictum.workflow.state import save_state
from tests.workflow.conftest import make_envelope, make_runtime


@pytest.mark.asyncio
async def test_set_stage_stage_id_changes_active_stage_and_preserves_evidence():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-set-stage
stages:
  - id: read-context
    tools: [Read]
  - id: implement
    entry:
      - condition: stage_complete("read-context")
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    tools: [Read]
"""
    )
    session = Session("behavior-set-stage", MemoryBackend())
    state = WorkflowState(
        session_id="behavior-set-stage",
        active_stage="read-context",
        completed_stages=[],
        approvals={"review": "approved"},
        evidence=WorkflowEvidence(
            reads=["spec.md"],
            stage_calls={"review": ["git push origin feature"]},
        ),
        blocked_reason="Tool is not allowed in this workflow stage",
        pending_approval={
            "required": True,
            "stage_id": "read-context",
            "message": "approve",
        },
        last_blocked_action={
            "tool": "Bash",
            "summary": "git push origin feature",
            "message": "Tool is not allowed in this workflow stage",
            "timestamp": "2026-04-04T00:00:00Z",
        },
    )
    state.ensure_defaults()
    await save_state(session, runtime.definition, state)

    await runtime.set_stage(session, "review")
    state = await runtime.state(session)

    assert state.active_stage == "review"
    assert state.completed_stages == ["read-context", "implement"]
    assert state.approvals == {"review": "approved"}
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls == {"review": ["git push origin feature"]}
    assert state.blocked_reason is None
    assert state.pending_approval == {"required": False}
    assert state.last_blocked_action is None


@pytest.mark.asyncio
async def test_set_stage_stage_id_rejects_unknown_stage():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-set-stage-unknown
stages:
  - id: implement
    tools: [Edit]
"""
    )
    session = Session("behavior-set-stage-unknown", MemoryBackend())

    with pytest.raises(ValueError, match='workflow: unknown set stage "review"'):
        await runtime.set_stage(session, "review")


@pytest.mark.asyncio
@pytest.mark.security
async def test_set_stage_to_approval_stage_still_requires_approval_before_advancing():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-set-stage-approval-barrier
stages:
  - id: implement
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: Review required before push
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
"""
    )
    session = Session("behavior-set-stage-approval-barrier", MemoryBackend())

    await runtime.set_stage(session, "review")

    decision = await runtime.evaluate(session, make_envelope("Bash", {"command": "git push origin feature"}))
    state = await runtime.state(session)

    assert decision.action == "pending_approval"
    assert decision.stage_id == "review"
    assert state.active_stage == "review"
    assert state.completed_stages == ["implement"]
    assert state.approvals == {}


@pytest.mark.asyncio
@pytest.mark.security
async def test_set_stage_backward_into_pre_approved_stage_preserves_approval():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: behavior-set-stage-preserved-approval
stages:
  - id: implement
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: Review required before push
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
"""
    )
    session = Session("behavior-set-stage-preserved-approval", MemoryBackend())
    state = WorkflowState(
        session_id="behavior-set-stage-preserved-approval",
        active_stage="push",
        completed_stages=["implement", "review"],
        approvals={"review": "approved"},
    )
    state.ensure_defaults()
    await save_state(session, runtime.definition, state)

    await runtime.set_stage(session, "review")

    decision = await runtime.evaluate(session, make_envelope("Bash", {"command": "git push origin feature"}))
    state = await runtime.state(session)

    assert decision.action == "allow"
    assert decision.stage_id == "push"
    assert state.active_stage == "push"
    assert state.completed_stages == ["implement", "review"]
    assert state.approvals == {"review": "approved"}

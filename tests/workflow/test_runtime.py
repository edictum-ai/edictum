from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from edictum import Edictum, EdictumDenied, EdictumToolError
from edictum.audit import AuditAction
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowCheck, WorkflowDefinition, WorkflowMetadata, WorkflowRuntime, WorkflowStage
from edictum.workflow.result import WorkflowEvidence, WorkflowState
from edictum.workflow.state import save_state

from .conftest import AutoApproveBackend, make_envelope, make_runtime, workflow_fixture_path


def _normalize_decision(action: str) -> str:
    if action == "pending_approval":
        return "pause"
    return action


async def _seed_state(runtime, session: Session, state: WorkflowState) -> None:
    state.ensure_defaults()
    await save_state(session, runtime.definition, state)


@pytest.mark.asyncio
async def test_shared_workflow_fixtures():
    path = workflow_fixture_path()
    with path.open("r", encoding="utf-8") as handle:
        suite = yaml.safe_load(handle)

    runtimes = {}
    for name, doc in suite["workflows"].items():
        runtimes[name] = make_runtime(yaml.safe_dump(doc, sort_keys=False))

    for fixture in suite["fixtures"]:
        runtime = runtimes[fixture["workflow"]]
        session = Session(fixture["initial_state"]["session_id"], MemoryBackend())
        initial = fixture["initial_state"]
        await _seed_state(
            runtime,
            session,
            WorkflowState(
                session_id=initial["session_id"],
                active_stage=initial["active_stage"],
                completed_stages=list(initial["completed_stages"]),
                approvals=dict(initial["approvals"]),
                evidence=WorkflowEvidence(
                    reads=list(initial["evidence"]["reads"]),
                    stage_calls={k: list(v) for k, v in initial["evidence"]["stage_calls"].items()},
                ),
            ),
        )

        for step in fixture["steps"]:
            envelope = make_envelope(step["call"]["tool"], step["call"]["args"])
            decision = await runtime.evaluate(session, envelope)
            expect = step["expect"]
            assert _normalize_decision(decision.action) == expect["decision"], step["id"]
            if expect.get("message_contains"):
                assert expect["message_contains"] in decision.reason, step["id"]
            if expect.get("approval_requested_for"):
                assert decision.audit is not None
                assert decision.audit["pending_approval"]["stage_id"] == expect["approval_requested_for"], step["id"]
            if decision.action == "allow" and step["execution"] == "success":
                await runtime.record_result(session, decision.stage_id, envelope)

            state = await runtime.state(session)
            assert state.active_stage == expect["active_stage"], step["id"]
            assert state.completed_stages == expect["completed_stages"], step["id"]
            assert state.approvals == expect["approvals"], step["id"]
            assert state.evidence.reads == expect["evidence"]["reads"], step["id"]
            assert state.evidence.stage_calls == expect["evidence"]["stage_calls"], step["id"]


@pytest.mark.asyncio
async def test_runtime_record_approval_and_reset():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: approval-reset
stages:
  - id: implement
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: need review
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
"""
    )
    session = Session("runtime-reset", MemoryBackend())

    edit = make_envelope("Edit", {"path": "src/app.py"})
    first = await runtime.evaluate(session, edit)
    await runtime.record_result(session, first.stage_id, edit)

    approval_gate = await runtime.evaluate(session, make_envelope("Bash", {"command": "git push origin feature"}))
    assert approval_gate.action == "pending_approval"

    await runtime.record_approval(session, "review")
    allowed = await runtime.evaluate(session, make_envelope("Bash", {"command": "git push origin feature"}))
    assert allowed.action == "allow"

    events = await runtime.reset(session, "implement")
    state = await runtime.state(session)
    assert state.active_stage == "implement"
    assert state.completed_stages == []
    assert state.approvals == {}
    assert state.pending_approval == {"required": False}
    assert state.blocked_reason is None
    assert len(events) == 1
    assert events[0]["action"] == AuditAction.WORKFLOW_STATE_UPDATED.value
    assert events[0]["workflow"]["name"] == "approval-reset"
    assert events[0]["workflow"]["active_stage"] == "implement"
    assert events[0]["workflow"]["pending_approval"] == {"required": False}


@pytest.mark.asyncio
async def test_workflow_state_persistence_round_trip_preserves_enriched_fields():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: snapshot-roundtrip
stages:
  - id: implement
    tools: [Edit]
"""
    )
    session = Session("snapshot-roundtrip", MemoryBackend())

    await _seed_state(
        runtime,
        session,
        WorkflowState(
            session_id="snapshot-roundtrip",
            active_stage="implement",
            blocked_reason="Only review-safe git commands allowed",
            pending_approval={
                "required": True,
                "stage_id": "implement",
                "message": "Approve after local review",
            },
            last_blocked_action={
                "tool": "Bash",
                "summary": "git push origin HEAD",
                "message": "Only review-safe git commands allowed",
                "timestamp": "2026-04-04T00:00:00Z",
            },
        ),
    )

    state = await runtime.state(session)

    assert state.blocked_reason == "Only review-safe git commands allowed"
    assert state.pending_approval == {
        "required": True,
        "stage_id": "implement",
        "message": "Approve after local review",
    }
    assert state.last_blocked_action == {
        "tool": "Bash",
        "summary": "git push origin HEAD",
        "message": "Only review-safe git commands allowed",
        "timestamp": "2026-04-04T00:00:00Z",
    }


@pytest.mark.asyncio
async def test_blocked_workflow_call_persists_blocked_snapshot():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: blocked-snapshot
stages:
  - id: implement
    tools: [Edit]
"""
    )
    session = Session("blocked-snapshot", MemoryBackend())

    decision = await runtime.evaluate(session, make_envelope("Bash", {"command": "git push origin HEAD"}))
    state = await runtime.state(session)

    assert decision.action == "block"
    assert state.blocked_reason == "Tool is not allowed in this workflow stage"
    assert state.pending_approval == {"required": False}
    assert state.last_blocked_action is not None
    assert state.last_blocked_action["tool"] == "Bash"
    assert state.last_blocked_action["summary"] == "git push origin HEAD"
    assert state.last_blocked_action["message"] == "Tool is not allowed in this workflow stage"


@pytest.mark.asyncio
async def test_pending_workflow_call_persists_pending_approval_snapshot():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: pending-snapshot
stages:
  - id: implement
    tools: [Edit]
  - id: review
    entry:
      - condition: stage_complete("implement")
    approval:
      message: need review
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
"""
    )
    session = Session("pending-snapshot", MemoryBackend())

    edit = make_envelope("Edit", {"path": "src/app.py"})
    decision = await runtime.evaluate(session, edit)
    await runtime.record_result(session, decision.stage_id, edit)

    approval_gate = await runtime.evaluate(session, make_envelope("Bash", {"command": "git push origin feature"}))
    state = await runtime.state(session)

    assert approval_gate.action == "pending_approval"
    assert state.blocked_reason is None
    assert state.pending_approval == {
        "required": True,
        "stage_id": "review",
        "message": "need review",
    }


@pytest.mark.asyncio
async def test_programmatic_workflow_check_enforces_regex_without_manual_compilation():
    runtime = WorkflowRuntime(
        WorkflowDefinition(
            api_version="edictum/v1",
            kind="Workflow",
            metadata=WorkflowMetadata(name="programmatic-check"),
            stages=(
                WorkflowStage(
                    id="verify",
                    tools=("Bash",),
                    checks=(
                        WorkflowCheck(
                            message="Only git status is allowed",
                            command_matches=r"^git status$",
                        ),
                    ),
                ),
            ),
        )
    )
    session = Session("programmatic-check", MemoryBackend())

    allowed = await runtime.evaluate(session, make_envelope("Bash", {"command": "git status"}))
    blocked = await runtime.evaluate(session, make_envelope("Bash", {"command": "rm -rf /"}))

    assert allowed.action == "allow"
    assert blocked.action == "block"
    assert blocked.reason == "Only git status is allowed"


@pytest.mark.asyncio
async def test_guard_run_workflow_evidence_and_approval(tmp_path: Path):
    guard = Edictum.from_yaml_string(
        """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: empty-bundle
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
""",
        backend=MemoryBackend(),
        workflow_content="""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: guard-workflow
stages:
  - id: read-context
    tools: [Read]
    exit:
      - condition: file_read("spec.md")
        message: Read spec first
  - id: review
    entry:
      - condition: stage_complete("read-context")
    approval:
      message: approve before push
  - id: push
    entry:
      - condition: stage_complete("review")
    tools: [Bash]
""",
        approval_backend=AutoApproveBackend(),
    )

    async def failing_read(path: str):
        raise RuntimeError("boom")

    with pytest.raises(EdictumToolError):
        await guard.run("Read", {"path": "spec.md"}, failing_read, session_id="guard-session")

    runtime = guard._workflow_runtime
    assert runtime is not None
    state = await runtime.state(Session("guard-session", guard.backend))
    assert state.evidence.reads == []

    with pytest.raises(EdictumDenied):
        await guard.run("Bash", {"command": "git push origin branch"}, lambda command: "ok", session_id="guard-session")

    result = await guard.run("Read", {"path": "spec.md"}, lambda path: "spec", session_id="guard-session")
    assert result == "spec"

    pushed = await guard.run(
        "Bash",
        {"command": "git push origin branch"},
        lambda command: "ok",
        session_id="guard-session",
    )
    assert pushed == "ok"

    state = await runtime.state(Session("guard-session", guard.backend))
    assert state.approvals["review"] == "approved"
    assert state.evidence.reads == ["spec.md"]
    assert state.evidence.stage_calls["push"] == ["git push origin branch"]

    actions = [event.action for event in guard.local_sink.events]
    assert AuditAction.WORKFLOW_STAGE_ADVANCED in actions
    assert AuditAction.WORKFLOW_COMPLETED in actions


@pytest.mark.asyncio
async def test_guard_run_ignores_invalid_workflow_evidence_after_execution():
    guard = Edictum.from_yaml_string(
        """
apiVersion: edictum/v1
kind: Ruleset
metadata:
  name: empty-bundle
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
""",
        backend=MemoryBackend(),
        workflow_content="""
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: invalid-evidence
stages:
  - id: execute
    tools: [Bash]
""",
    )

    result = await guard.run(
        "Bash",
        {"command": "git push origin branch\r"},
        lambda command: "ok",
        session_id="invalid-evidence-session",
    )

    assert result == "ok"
    runtime = guard._workflow_runtime
    assert runtime is not None
    session = Session("invalid-evidence-session", guard.backend)
    state = await runtime.state(session)
    assert state.active_stage == "execute"
    assert state.evidence.stage_calls == {}
    assert await session.execution_count() == 1
    actions = [event.action for event in guard.local_sink.events]
    assert AuditAction.CALL_EXECUTED in actions


@pytest.mark.asyncio
async def test_auto_advanced_stage_persists_before_block_return():
    runtime = make_runtime(
        """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: persist-advance
stages:
  - id: prepare
    exit:
      - condition: file_read("spec.md")
        message: spec required
  - id: execute
    tools: [Bash]
"""
    )
    session = Session("persist-advance", MemoryBackend())
    await _seed_state(
        runtime,
        session,
        WorkflowState(
            session_id="persist-advance",
            active_stage="prepare",
            completed_stages=[],
            approvals={},
            evidence=WorkflowEvidence(
                reads=["spec.md"],
                stage_calls={},
            ),
        ),
    )

    decision = await runtime.evaluate(session, make_envelope("Read", {"path": "other.md"}))

    assert decision.action == "block"
    state = await runtime.state(session)
    assert state.active_stage == "execute"
    assert state.completed_stages == ["prepare"]

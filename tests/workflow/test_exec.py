from __future__ import annotations

import asyncio

import pytest

from edictum.envelope import create_envelope
from edictum.session import Session
from edictum.storage import MemoryBackend
from edictum.workflow import WorkflowRuntime, load_workflow_string
from edictum.workflow.evaluator import FactResult
from edictum.workflow.result import WorkflowEvaluation, WorkflowState
from edictum.workflow.state import save_state

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


@pytest.mark.asyncio
async def test_exec_evaluator_times_out(monkeypatch):
    from edictum.workflow import evaluator_exec

    runtime = WorkflowRuntime(
        load_workflow_string(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: exec-timeout
stages:
  - id: wait-for-check
    exit:
      - condition: exec("python3 -c \\"import time; time.sleep(1)\\"", exit_code=0)
        message: command must finish
  - id: verify
    entry:
      - condition: stage_complete("wait-for-check")
    tools: [Bash]
"""
        ),
        exec_evaluator_enabled=True,
    )
    session = Session("exec-timeout", MemoryBackend())
    monkeypatch.setattr(evaluator_exec, "MAX_EXEC_TIMEOUT_SECONDS", 0.01)

    with pytest.raises(ValueError, match="timed out"):
        await runtime.evaluate(session, create_envelope("Bash", {"command": "python3 -V"}))


@pytest.mark.asyncio
async def test_runtime_evaluation_stops_after_stage_iteration_limit(monkeypatch):
    runtime = WorkflowRuntime(
        load_workflow_string(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: iteration-limit
stages:
  - id: review
    tools: [Read]
"""
        )
    )
    session = Session("iteration-limit", MemoryBackend())

    monkeypatch.setattr(
        runtime,
        "evaluate_current_stage",
        lambda stage, envelope: (False, WorkflowEvaluation(), None),
    )

    async def _complete(stage, state, envelope, has_next):
        return WorkflowEvaluation(), True

    monkeypatch.setattr(runtime, "evaluate_completion", _complete)
    monkeypatch.setattr(runtime, "next_index", lambda stage_id: (0, True))

    with pytest.raises(RuntimeError, match="stage iteration limit"):
        await runtime.evaluate(session, create_envelope("Read", {"path": "spec.md"}))


@pytest.mark.asyncio
async def test_exec_gate_does_not_serialize_other_sessions_in_evaluate():
    runtime = WorkflowRuntime(
        load_workflow_string(
            """
apiVersion: edictum/v1
kind: Workflow
metadata:
  name: exec-boundary
stages:
  - id: verify
    exit:
      - condition: exec("python3 -c \\"raise SystemExit(0)\\"", exit_code=0)
        message: command must pass
  - id: run
    entry:
      - condition: stage_complete("verify")
    tools: [Bash]
"""
        ),
        exec_evaluator_enabled=True,
    )
    backend = MemoryBackend()
    slow_session = Session("exec-slow", backend)
    fast_session = Session("exec-fast", backend)

    started = asyncio.Event()
    release = asyncio.Event()

    class SlowExecEvaluator:
        async def evaluate(self, req):
            started.set()
            await release.wait()
            return FactResult(
                passed=True,
                evidence="released",
                kind="exec",
                condition=req.parsed.condition,
                message=req.gate.message,
                stage_id=req.stage.id,
                workflow=req.definition.metadata.name,
            )

    runtime.evaluators["exec"] = SlowExecEvaluator()
    await save_state(
        fast_session,
        runtime.definition,
        WorkflowState(session_id="exec-fast", active_stage=""),
    )

    slow_task = asyncio.create_task(runtime.evaluate(slow_session, create_envelope("Bash", {"command": "python3 -V"})))
    await started.wait()

    fast_result = await asyncio.wait_for(
        runtime.evaluate(fast_session, create_envelope("Bash", {"command": "echo ok"})),
        timeout=0.1,
    )

    assert fast_result.action == "allow"
    release.set()
    slow_result = await slow_task
    assert slow_result.action == "allow"


@pytest.mark.asyncio
async def test_exec_gate_does_not_serialize_other_sessions_in_record_result():
    runtime = WorkflowRuntime(load_workflow_string(EXEC_WORKFLOW), exec_evaluator_enabled=True)
    backend = MemoryBackend()
    slow_session = Session("record-slow", backend)
    fast_session = Session("record-fast", backend)

    started = asyncio.Event()
    release = asyncio.Event()

    class SlowExecEvaluator:
        async def evaluate(self, req):
            started.set()
            await release.wait()
            return FactResult(
                passed=True,
                evidence="released",
                kind="exec",
                condition=req.parsed.condition,
                message=req.gate.message,
                stage_id=req.stage.id,
                workflow=req.definition.metadata.name,
            )

    runtime.evaluators["exec"] = SlowExecEvaluator()
    await save_state(
        fast_session,
        runtime.definition,
        WorkflowState(session_id="record-fast", active_stage=""),
    )

    slow_task = asyncio.create_task(
        runtime.record_result(slow_session, "verify", create_envelope("Bash", {"command": "python3 -V"}))
    )
    await started.wait()

    fast_result = await asyncio.wait_for(
        runtime.evaluate(fast_session, create_envelope("Bash", {"command": "echo ok"})),
        timeout=0.1,
    )

    assert fast_result.action == "allow"
    release.set()
    await slow_task

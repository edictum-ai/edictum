"""Workflow evaluation helpers."""

from __future__ import annotations

from copy import deepcopy
from typing import TYPE_CHECKING, Any

from edictum.envelope import ToolCall
from edictum.workflow.definition import WorkflowGate, WorkflowStage
from edictum.workflow.evaluator import EvaluateRequest, FactResult, gate_record, parse_condition
from edictum.workflow.result import WorkflowEvaluation, WorkflowState

if TYPE_CHECKING:
    from edictum.session import Session
    from edictum.workflow.runtime import WorkflowRuntime


async def evaluate_runtime(runtime: WorkflowRuntime, session: Session, envelope: ToolCall) -> WorkflowEvaluation:
    state = await runtime.load_state(session)
    if not state.active_stage:
        return WorkflowEvaluation(action="allow")

    changed = False
    events: list[dict[str, Any]] = []

    max_iterations = len(runtime.definition.stages) + 1
    for _ in range(max_iterations):
        stage = runtime.definition.stage_by_id(state.active_stage)
        if stage is None:
            raise ValueError(f'workflow: active stage "{state.active_stage}" not found')

        allowed, allowed_eval, invalid_eval = runtime.evaluate_current_stage(stage, envelope)
        if allowed:
            if changed:
                await runtime.save_state(session, state)
            allowed_eval.events.extend(events)
            return allowed_eval

        next_index, has_next = runtime.next_index(stage.id)
        if invalid_eval is not None and not has_next:
            if changed:
                await runtime.save_state(session, state)
            invalid_eval.events.extend(events)
            return invalid_eval

        completion, complete = await runtime.evaluate_completion(stage, state, envelope, has_next)
        if not complete:
            if completion.action:
                if changed:
                    await runtime.save_state(session, state)
                completion.events.extend(events)
                return completion
            if invalid_eval is not None:
                if changed:
                    await runtime.save_state(session, state)
                invalid_eval.events.extend(events)
                return invalid_eval
            if changed:
                await runtime.save_state(session, state)
            completion.events.extend(events)
            return completion

        if not state.completed(stage.id):
            state.completed_stages.append(stage.id)

        if not has_next:
            state.active_stage = ""
            events.append(workflow_progress_event("workflow_completed", runtime.definition.metadata.name, stage.id, ""))
            await runtime.save_state(session, state)
            return WorkflowEvaluation(action="allow", events=events)

        next_stage_id = runtime.definition.stages[next_index].id
        state.active_stage = next_stage_id
        events.append(
            workflow_progress_event(
                "workflow_stage_advanced",
                runtime.definition.metadata.name,
                stage.id,
                next_stage_id,
            )
        )
        changed = True

    raise RuntimeError(f"workflow: exceeded stage iteration limit ({max_iterations})")


async def evaluate_completion(
    runtime: WorkflowRuntime,
    stage: WorkflowStage,
    state: WorkflowState,
    envelope: ToolCall,
    has_next: bool,
) -> tuple[WorkflowEvaluation, bool]:
    if stage.exit:
        failure, blocked = await evaluate_gates(runtime, stage, state, envelope, stage.exit)
        if blocked:
            return failure, False

    if stage.approval is not None and state.approvals.get(stage.id) != "approved":
        audit = workflow_metadata(
            runtime.definition.metadata.name,
            stage.id,
            "approval",
            "stage boundary",
            False,
            "",
            {"approval_requested_for": stage.id},
        )
        return (
            evaluation_from_record(
                "pending_approval",
                stage.id,
                stage.approval.message,
                audit,
                gate_record(
                    FactResult(
                        passed=False,
                        evidence="",
                        kind="approval",
                        condition="stage boundary",
                        message=stage.approval.message,
                        stage_id=stage.id,
                        workflow=runtime.definition.metadata.name,
                        extra_audit={"approval_requested_for": stage.id},
                    ),
                    False,
                ),
            ),
            False,
        )

    if not has_next:
        if stage.exit or stage.approval is not None:
            return WorkflowEvaluation(action="allow"), True
        return WorkflowEvaluation(), False

    next_stage = runtime.definition.stages[runtime.must_index(stage.id) + 1]
    next_state = clone_state(state)
    if not next_state.completed(stage.id):
        next_state.completed_stages.append(stage.id)
    failure, blocked = await evaluate_gates(runtime, next_stage, next_state, envelope, next_stage.entry)
    if blocked:
        return failure, False
    return WorkflowEvaluation(), True


async def evaluate_gates(
    runtime: WorkflowRuntime,
    stage: WorkflowStage,
    state: WorkflowState,
    envelope: ToolCall,
    gates: tuple[WorkflowGate, ...],
) -> tuple[WorkflowEvaluation, bool]:
    records: list[dict[str, Any]] = []
    for gate in gates:
        parsed = parse_condition(gate.condition)
        evaluator = runtime.evaluators[parsed.kind]
        result = await evaluator.evaluate(
            EvaluateRequest(
                definition=runtime.definition,
                stage=stage,
                gate=gate,
                parsed=parsed,
                state=state,
                call=envelope,
            )
        )
        record = gate_record(result, result.passed)
        records.append(record)
        if not result.passed:
            return (
                WorkflowEvaluation(
                    action="block",
                    reason=result.message,
                    stage_id=stage.id,
                    records=records,
                    audit=workflow_metadata(
                        runtime.definition.metadata.name,
                        stage.id,
                        result.kind,
                        result.condition,
                        False,
                        result.evidence,
                        result.extra_audit,
                    ),
                ),
                True,
            )
    return WorkflowEvaluation(records=records), False


def evaluation_from_record(
    action: str,
    stage_id: str,
    reason: str,
    audit: dict[str, Any],
    record: dict[str, Any],
) -> WorkflowEvaluation:
    return WorkflowEvaluation(
        action=action,
        reason=reason,
        stage_id=stage_id,
        records=[record],
        audit=audit,
    )


def workflow_progress_event(action: str, name: str, from_stage_id: str, to_stage_id: str) -> dict[str, Any]:
    workflow: dict[str, Any] = {
        "workflow_name": name,
        "stage_id": from_stage_id,
    }
    if to_stage_id:
        workflow["to_stage_id"] = to_stage_id
    return {
        "action": action,
        "workflow": workflow,
    }


def workflow_metadata(
    name: str,
    stage_id: str,
    kind: str,
    condition: str,
    passed: bool,
    evidence: str,
    extra: dict[str, Any] | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "workflow_name": name,
        "stage_id": stage_id,
        "gate_kind": kind,
        "gate_condition": condition,
        "gate_passed": passed,
        "gate_evidence": evidence,
    }
    if extra:
        metadata.update(extra)
    return metadata


def clone_state(state: WorkflowState) -> WorkflowState:
    return WorkflowState(
        session_id=state.session_id,
        active_stage=state.active_stage,
        completed_stages=list(state.completed_stages),
        approvals=dict(state.approvals),
        evidence=deepcopy(state.evidence),
    )

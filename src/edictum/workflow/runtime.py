"""Workflow runtime."""

from __future__ import annotations

import asyncio
from typing import Any

from edictum.envelope import ToolEnvelope
from edictum.session import Session
from edictum.workflow.definition import WorkflowDefinition, WorkflowStage
from edictum.workflow.evaluator import (
    ApprovalEvaluator,
    CommandEvaluator,
    FileReadEvaluator,
    StageCompleteEvaluator,
    uses_exec_condition,
)
from edictum.workflow.evaluator_exec import ExecEvaluator
from edictum.workflow.result import WorkflowEvaluation, WorkflowState
from edictum.workflow.runtime_eval import (
    evaluate_completion,
    evaluate_gates,
    evaluate_runtime,
    evaluation_from_record,
    workflow_metadata,
    workflow_progress_event,
)
from edictum.workflow.state import load_state, record_approval, record_result, save_state


class WorkflowRuntime:
    """Evaluate and persist one workflow definition."""

    def __init__(self, definition: WorkflowDefinition, *, exec_evaluator_enabled: bool = False):
        definition.validate()
        if uses_exec_condition(definition) and not exec_evaluator_enabled:
            raise ValueError("workflow: exec(...) conditions require exec_evaluator_enabled=True")

        evaluators: dict[str, Any] = {
            "stage_complete": StageCompleteEvaluator(),
            "file_read": FileReadEvaluator(),
            "approval": ApprovalEvaluator(),
            "command_matches": CommandEvaluator(),
            "command_not_matches": CommandEvaluator(),
        }
        if exec_evaluator_enabled:
            evaluators["exec"] = ExecEvaluator()

        self.definition = definition
        self.evaluators = evaluators
        self._lock = asyncio.Lock()

    async def state(self, session: Session) -> WorkflowState:
        async with self._lock:
            return await self.load_state(session)

    async def load_state(self, session: Session) -> WorkflowState:
        return await load_state(session, self.definition)

    async def save_state(self, session: Session, state: WorkflowState) -> None:
        await save_state(session, self.definition, state)

    async def evaluate(self, session: Session, envelope: ToolEnvelope) -> WorkflowEvaluation:
        async with self._lock:
            return await evaluate_runtime(self, session, envelope)

    async def reset(self, session: Session, stage_id: str) -> None:
        async with self._lock:
            idx = self.definition.stage_index(stage_id)
            if idx is None:
                raise ValueError(f'workflow: unknown reset stage "{stage_id}"')

            state = await self.load_state(session)
            state.active_stage = stage_id
            state.completed_stages = stage_ids(self.definition.stages[:idx])
            for stage in self.definition.stages[idx:]:
                state.approvals.pop(stage.id, None)
                state.evidence.stage_calls.pop(stage.id, None)
            if idx == 0:
                state.evidence.reads = []
            await self.save_state(session, state)

    async def record_approval(self, session: Session, stage_id: str) -> None:
        async with self._lock:
            if self.definition.stage_by_id(stage_id) is None:
                raise ValueError(f'workflow: unknown approval stage "{stage_id}"')
            state = await self.load_state(session)
            record_approval(state, stage_id)
            await self.save_state(session, state)

    async def record_result(self, session: Session, stage_id: str, envelope: ToolEnvelope) -> list[dict[str, Any]]:
        if not stage_id:
            return []
        async with self._lock:
            state = await self.load_state(session)
            record_result(state, stage_id, envelope)
            events = await self.advance_after_success(state, stage_id, envelope)
            await self.save_state(session, state)
            return events

    def evaluate_current_stage(
        self,
        stage: WorkflowStage,
        envelope: ToolEnvelope,
    ) -> tuple[bool, WorkflowEvaluation, WorkflowEvaluation | None]:
        if stage_is_boundary_only(stage):
            return False, WorkflowEvaluation(), None
        if not tool_allowed(stage, envelope):
            block = evaluation_from_record(
                "block",
                stage.id,
                "Tool is not allowed in this workflow stage",
                workflow_metadata(
                    self.definition.metadata.name,
                    stage.id,
                    "tools",
                    ",".join(stage.tools),
                    False,
                    envelope.tool_name,
                    None,
                ),
                {
                    "name": f"{self.definition.metadata.name}:{stage.id}:tools",
                    "type": "workflow_gate",
                    "passed": False,
                    "message": "Tool is not allowed in this workflow stage",
                    "metadata": {
                        "workflow_name": self.definition.metadata.name,
                        "stage_id": stage.id,
                        "gate_kind": "tools",
                        "gate_condition": ",".join(stage.tools),
                        "gate_passed": False,
                        "gate_evidence": envelope.tool_name,
                    },
                },
            )
            return False, WorkflowEvaluation(), block

        for check in stage.checks:
            passed, condition = evaluate_check(check, envelope)
            if not passed:
                block = evaluation_from_record(
                    "block",
                    stage.id,
                    check.message,
                    workflow_metadata(
                        self.definition.metadata.name,
                        stage.id,
                        "check",
                        condition,
                        False,
                        envelope.bash_command or "",
                        None,
                    ),
                    {
                        "name": f"{self.definition.metadata.name}:{stage.id}:check",
                        "type": "workflow_gate",
                        "passed": False,
                        "message": check.message,
                        "metadata": {
                            "workflow_name": self.definition.metadata.name,
                            "stage_id": stage.id,
                            "gate_kind": "check",
                            "gate_condition": condition,
                            "gate_passed": False,
                            "gate_evidence": envelope.bash_command or "",
                        },
                    },
                )
                return False, WorkflowEvaluation(), block

        condition = "tools" if not stage.tools else ",".join(stage.tools)
        record = {
            "name": f"{self.definition.metadata.name}:{stage.id}:tools",
            "type": "workflow_gate",
            "passed": True,
            "message": "tool allowed in active stage",
            "metadata": {
                "workflow_name": self.definition.metadata.name,
                "stage_id": stage.id,
                "gate_kind": "tools",
                "gate_condition": condition,
                "gate_passed": True,
                "gate_evidence": envelope.tool_name,
            },
        }
        return (
            True,
            evaluation_from_record(
                "allow",
                stage.id,
                "",
                workflow_metadata(
                    self.definition.metadata.name,
                    stage.id,
                    "tools",
                    condition,
                    True,
                    envelope.tool_name,
                    None,
                ),
                record,
            ),
            None,
        )

    async def evaluate_completion(
        self,
        stage: WorkflowStage,
        state: WorkflowState,
        envelope: ToolEnvelope,
        has_next: bool,
    ) -> tuple[WorkflowEvaluation, bool]:
        return await evaluate_completion(self, stage, state, envelope, has_next)

    async def evaluate_gates(
        self,
        stage: WorkflowStage,
        state: WorkflowState,
        envelope: ToolEnvelope,
        gates,
    ) -> tuple[WorkflowEvaluation, bool]:
        return await evaluate_gates(self, stage, state, envelope, gates)

    async def advance_after_success(
        self,
        state: WorkflowState,
        stage_id: str,
        envelope: ToolEnvelope,
    ) -> list[dict[str, Any]]:
        if state.active_stage != stage_id:
            return []
        stage = self.definition.stage_by_id(stage_id)
        if stage is None:
            raise ValueError(f'workflow: active stage "{stage_id}" not found')
        _, has_next = self.next_index(stage.id)
        if has_next:
            return []
        if stage.exit:
            failure, denied = await self.evaluate_gates(stage, state, envelope, stage.exit)
            if denied:
                return []
        if stage.approval is not None and state.approvals.get(stage.id) != "approved":
            return []
        if not state.completed(stage.id):
            state.completed_stages.append(stage.id)
        state.active_stage = ""
        return [workflow_progress_event("workflow_completed", self.definition.metadata.name, stage.id, "")]

    def next_index(self, stage_id: str) -> tuple[int, bool]:
        next_idx = self.must_index(stage_id) + 1
        return next_idx, next_idx < len(self.definition.stages)

    def must_index(self, stage_id: str) -> int:
        idx = self.definition.stage_index(stage_id)
        if idx is None:  # pragma: no cover - guarded by validated active stages
            raise ValueError(f'workflow: stage "{stage_id}" not found')
        return idx


def tool_allowed(stage, envelope: ToolEnvelope) -> bool:
    if not stage.tools:
        return True
    return envelope.tool_name in stage.tools


def stage_is_boundary_only(stage) -> bool:
    return not stage.tools and not stage.checks and (stage.approval is not None or bool(stage.exit))


def evaluate_check(check, envelope: ToolEnvelope) -> tuple[bool, str]:
    command = envelope.bash_command or ""
    if check.command_matches_re is not None and check.command_matches is not None:
        return bool(check.command_matches_re.search(command)), check.command_matches
    if check.command_not_matches_re is not None and check.command_not_matches is not None:
        return not check.command_not_matches_re.search(command), check.command_not_matches
    return True, ""


def stage_ids(stages) -> list[str]:
    return [stage.id for stage in stages]

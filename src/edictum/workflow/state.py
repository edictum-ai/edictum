"""Workflow state persistence helpers."""

from __future__ import annotations

import json

from edictum.envelope import ToolEnvelope
from edictum.session import Session
from edictum.workflow.result import WorkflowEvidence, WorkflowState

APPROVED_STATUS = "approved"
MAX_WORKFLOW_EVIDENCE_ITEMS = 1000


def workflow_state_key(name: str) -> str:
    return f"workflow:{name}:state"


async def load_state(session: Session, definition) -> WorkflowState:
    raw = await session.get_value(workflow_state_key(definition.metadata.name))
    if raw is None:
        state = WorkflowState(
            session_id=session.session_id,
            active_stage=definition.stages[0].id,
        )
        state.ensure_defaults()
        return state

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"workflow: decode persisted state: {exc}") from exc

    evidence_data = data.get("evidence") or {}
    state = WorkflowState(
        session_id=session.session_id,
        active_stage=data.get("active_stage", ""),
        completed_stages=list(data.get("completed_stages") or []),
        approvals=dict(data.get("approvals") or {}),
        evidence=WorkflowEvidence(
            reads=list(evidence_data.get("reads") or []),
            stage_calls={key: list(value) for key, value in (evidence_data.get("stage_calls") or {}).items()},
        ),
    )
    state.ensure_defaults()
    if state.active_stage and definition.stage_by_id(state.active_stage) is None:
        raise ValueError(f'workflow: persisted active stage "{state.active_stage}" does not exist')
    return state


async def save_state(session: Session, definition, state: WorkflowState) -> None:
    state.session_id = session.session_id
    state.ensure_defaults()
    try:
        raw = json.dumps(
            {
                "session_id": state.session_id,
                "active_stage": state.active_stage,
                "completed_stages": state.completed_stages,
                "approvals": state.approvals,
                "evidence": {
                    "reads": state.evidence.reads,
                    "stage_calls": state.evidence.stage_calls,
                },
            }
        )
    except TypeError as exc:
        raise ValueError(f"workflow: encode persisted state: {exc}") from exc
    await session.set_value(workflow_state_key(definition.metadata.name), raw)


def record_approval(state: WorkflowState, stage_id: str) -> None:
    state.ensure_defaults()
    state.approvals[stage_id] = APPROVED_STATUS


def record_result(state: WorkflowState, stage_id: str, envelope: ToolEnvelope) -> None:
    state.ensure_defaults()
    if envelope.tool_name == "Read" and envelope.file_path:
        state.evidence.reads = _append_unique_capped(
            state.evidence.reads,
            envelope.file_path,
            MAX_WORKFLOW_EVIDENCE_ITEMS,
        )
        return
    if envelope.tool_name == "Bash" and envelope.bash_command:
        calls = state.evidence.stage_calls.get(stage_id, [])
        state.evidence.stage_calls[stage_id] = _append_capped(
            calls,
            envelope.bash_command,
            MAX_WORKFLOW_EVIDENCE_ITEMS,
        )


def _append_unique_capped(items: list[str], item: str, limit: int) -> list[str]:
    if item in items:
        return items
    return _append_capped(items, item, limit)


def _append_capped(items: list[str], item: str, limit: int) -> list[str]:
    if len(items) >= limit:
        return items
    return [*items, item]

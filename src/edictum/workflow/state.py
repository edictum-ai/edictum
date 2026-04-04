"""Workflow state persistence helpers."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from edictum.envelope import ToolCall
from edictum.session import Session
from edictum.workflow.result import (
    WorkflowEvaluation,
    WorkflowEvidence,
    WorkflowState,
    default_pending_approval,
)

APPROVED_STATUS = "approved"
MAX_WORKFLOW_EVIDENCE_ITEMS = 1000
MAX_WORKFLOW_EVIDENCE_LENGTH = 4096


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
        blocked_reason=data.get("blocked_reason"),
        pending_approval=_coerce_pending_approval(data.get("pending_approval")),
        last_blocked_action=_coerce_optional_dict(data.get("last_blocked_action")),
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
                "blocked_reason": state.blocked_reason,
                "pending_approval": state.pending_approval,
                "last_blocked_action": state.last_blocked_action,
            }
        )
    except TypeError as exc:
        raise ValueError(f"workflow: encode persisted state: {exc}") from exc
    await session.set_value(workflow_state_key(definition.metadata.name), raw)


def record_approval(state: WorkflowState, stage_id: str) -> None:
    state.ensure_defaults()
    state.approvals[stage_id] = APPROVED_STATUS
    clear_runtime_status(state)


def record_result(state: WorkflowState, stage_id: str, envelope: ToolCall) -> None:
    state.ensure_defaults()
    if envelope.tool_name == "Read" and envelope.file_path:
        state.evidence.reads = _append_unique_capped(
            state.evidence.reads,
            _validate_evidence_string(envelope.file_path),
            MAX_WORKFLOW_EVIDENCE_ITEMS,
        )
        return
    if envelope.tool_name == "Bash" and envelope.bash_command:
        calls = state.evidence.stage_calls.get(stage_id, [])
        state.evidence.stage_calls[stage_id] = _append_capped(
            calls,
            _validate_evidence_string(envelope.bash_command),
            MAX_WORKFLOW_EVIDENCE_ITEMS,
        )


def clear_runtime_status(state: WorkflowState) -> None:
    state.ensure_defaults()
    state.blocked_reason = None
    state.pending_approval = default_pending_approval()


def apply_evaluation_status(state: WorkflowState, evaluation: WorkflowEvaluation, envelope: ToolCall) -> bool:
    state.ensure_defaults()
    changed = False

    if evaluation.action == "block":
        if state.blocked_reason != evaluation.reason:
            state.blocked_reason = evaluation.reason
            changed = True
        if state.pending_approval != default_pending_approval():
            state.pending_approval = default_pending_approval()
            changed = True
        blocked_action = build_last_blocked_action(envelope, evaluation.reason)
        if state.last_blocked_action != blocked_action:
            state.last_blocked_action = blocked_action
            changed = True
        return changed

    if evaluation.action == "pending_approval":
        pending_approval = {
            "required": True,
            "stage_id": evaluation.stage_id,
            "message": evaluation.reason,
        }
        if state.pending_approval != pending_approval:
            state.pending_approval = pending_approval
            changed = True
        if state.blocked_reason is not None:
            state.blocked_reason = None
            changed = True
        return changed

    if state.blocked_reason is not None or state.pending_approval != default_pending_approval():
        clear_runtime_status(state)
        changed = True
    return changed


def build_workflow_snapshot(definition, state: WorkflowState) -> dict[str, Any]:
    state.ensure_defaults()
    snapshot: dict[str, Any] = {
        "name": definition.metadata.name,
        "active_stage": state.active_stage,
        "completed_stages": list(state.completed_stages),
        "blocked_reason": state.blocked_reason,
        "pending_approval": deepcopy(state.pending_approval),
    }
    version = getattr(definition.metadata, "version", None)
    if version:
        snapshot["version"] = version
    if state.last_blocked_action is not None:
        snapshot["last_blocked_action"] = deepcopy(state.last_blocked_action)
    return snapshot


def build_workflow_event(action: str, workflow: dict[str, Any]) -> dict[str, Any]:
    return {"action": action, "workflow": workflow}


def hydrate_workflow_events(definition, state: WorkflowState, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not events:
        return []
    workflow = build_workflow_snapshot(definition, state)
    return [build_workflow_event(str(event.get("action", "")), workflow) for event in events]


def build_last_blocked_action(envelope: ToolCall, message: str) -> dict[str, str]:
    return {
        "tool": envelope.tool_name,
        "summary": summarize_tool_call(envelope),
        "message": _safe_status_text(message, ""),
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def summarize_tool_call(envelope: ToolCall) -> str:
    if envelope.bash_command:
        return _safe_status_text(envelope.bash_command, envelope.tool_name)
    if envelope.file_path:
        return _safe_status_text(envelope.file_path, envelope.tool_name)
    return envelope.tool_name


def _append_unique_capped(items: list[str], item: str, limit: int) -> list[str]:
    if item in items:
        return items
    return _append_capped(items, item, limit)


def _append_capped(items: list[str], item: str, limit: int) -> list[str]:
    if len(items) >= limit:
        return items
    return [*items, item]


def _validate_evidence_string(value: str) -> str:
    if len(value) > MAX_WORKFLOW_EVIDENCE_LENGTH:
        raise ValueError(f"workflow: evidence string too long ({len(value)} chars)")
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            raise ValueError("workflow: evidence string contains control characters")
    return value


def _safe_status_text(value: str, fallback: str) -> str:
    try:
        return _validate_evidence_string(value)
    except ValueError:
        return fallback


def _coerce_pending_approval(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return default_pending_approval()
    pending = dict(value)
    pending.setdefault("required", False)
    return pending


def _coerce_optional_dict(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return dict(value)

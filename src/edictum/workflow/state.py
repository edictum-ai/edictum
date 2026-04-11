"""Workflow state persistence helpers."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from edictum.audit import RedactionPolicy
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
_REDACTION_POLICY = RedactionPolicy()


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
    mcp_raw = evidence_data.get("mcp_results") or {}
    state = WorkflowState(
        session_id=session.session_id,
        active_stage=data.get("active_stage", ""),
        completed_stages=list(data.get("completed_stages") or []),
        approvals=dict(data.get("approvals") or {}),
        evidence=WorkflowEvidence(
            reads=list(evidence_data.get("reads") or []),
            stage_calls={key: list(value) for key, value in (evidence_data.get("stage_calls") or {}).items()},
            mcp_results={k: [_coerce_mcp_result(r) for r in v] for k, v in mcp_raw.items()},
        ),
        blocked_reason=data.get("blocked_reason"),
        pending_approval=_coerce_pending_approval(data.get("pending_approval")),
        last_blocked_action=_coerce_optional_dict(data.get("last_blocked_action")),
        last_recorded_evidence=_coerce_recorded_evidence(data.get("last_recorded_evidence")),
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
                    "mcp_results": state.evidence.mcp_results,
                },
                "blocked_reason": state.blocked_reason,
                "pending_approval": state.pending_approval,
                "last_blocked_action": state.last_blocked_action,
                "last_recorded_evidence": state.last_recorded_evidence,
            }
        )
    except TypeError as exc:
        raise ValueError(f"workflow: encode persisted state: {exc}") from exc
    await session.set_value(workflow_state_key(definition.metadata.name), raw)


def record_approval(state: WorkflowState, stage_id: str) -> None:
    state.ensure_defaults()
    state.approvals[stage_id] = APPROVED_STATUS
    clear_runtime_status(state)


def record_result(state: WorkflowState, stage_id: str, envelope: ToolCall, mcp_result: dict | None = None) -> None:
    state.ensure_defaults()
    recorded_evidence_fields = build_last_recorded_evidence_fields(envelope)
    if _recorded_evidence_changed(state.last_recorded_evidence, recorded_evidence_fields):
        state.last_recorded_evidence = build_last_recorded_evidence(recorded_evidence_fields)
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
    if mcp_result is not None:
        existing = state.evidence.mcp_results.get(envelope.tool_name, [])
        state.evidence.mcp_results[envelope.tool_name] = _append_dict_capped(
            existing, _coerce_mcp_result(mcp_result), MAX_WORKFLOW_EVIDENCE_ITEMS
        )


def clear_runtime_status(state: WorkflowState) -> None:
    state.ensure_defaults()
    state.blocked_reason = None
    state.pending_approval = default_pending_approval()


def set_stage_pending_approval(state: WorkflowState, stage_id: str, message: str, *, required: bool) -> None:
    state.ensure_defaults()
    if not required:
        state.pending_approval = default_pending_approval()
        return
    state.pending_approval = _build_pending_approval(stage_id, message)


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
        blocked_action_fields = build_last_blocked_action_fields(envelope, evaluation.reason)
        if _blocked_action_changed(state.last_blocked_action, blocked_action_fields):
            state.last_blocked_action = build_last_blocked_action(blocked_action_fields)
            changed = True
        return changed

    if evaluation.action == "pending_approval":
        pending_approval = _build_pending_approval(evaluation.stage_id, evaluation.reason)
        if state.pending_approval != pending_approval:
            state.pending_approval = pending_approval
            changed = True
        if state.blocked_reason is not None:
            state.blocked_reason = None
            changed = True
        if state.last_blocked_action is not None:
            state.last_blocked_action = None
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
    if state.last_recorded_evidence is not None:
        snapshot["last_recorded_evidence"] = deepcopy(state.last_recorded_evidence)
    return snapshot


def build_workflow_event(action: str, workflow: dict[str, Any]) -> dict[str, Any]:
    return {"action": action, "workflow": workflow}


def hydrate_workflow_events(definition, state: WorkflowState, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not events:
        return []
    snapshot = build_workflow_snapshot(definition, state)
    hydrated: list[dict[str, Any]] = []
    for event in events:
        workflow = deepcopy(snapshot)
        event_workflow = event.get("workflow")
        if isinstance(event_workflow, dict):
            workflow.update(event_workflow)
        hydrated.append(build_workflow_event(str(event.get("action", "")), workflow))
    return hydrated


def build_last_blocked_action_fields(envelope: ToolCall, message: str) -> dict[str, str]:
    return {
        "tool": envelope.tool_name,
        "summary": summarize_tool_call(envelope),
        "message": _safe_status_text(message, ""),
    }


def build_last_blocked_action(fields: dict[str, str]) -> dict[str, str]:
    return {
        "tool": fields["tool"],
        "summary": fields["summary"],
        "message": fields["message"],
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def build_last_recorded_evidence_fields(envelope: ToolCall) -> dict[str, str]:
    return {
        "tool": envelope.tool_name,
        "summary": summarize_tool_call(envelope),
    }


def build_last_recorded_evidence(fields: dict[str, str]) -> dict[str, str]:
    return {
        "tool": fields["tool"],
        "summary": fields["summary"],
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def summarize_tool_call(envelope: ToolCall) -> str:
    if envelope.bash_command:
        return _safe_status_text(_REDACTION_POLICY.redact_bash_command(envelope.bash_command), envelope.tool_name)
    if envelope.file_path:
        return _safe_status_text(_REDACTION_POLICY.redact_bash_command(envelope.file_path), envelope.tool_name)
    return envelope.tool_name


def _blocked_action_changed(current: dict[str, Any] | None, fields: dict[str, str]) -> bool:
    if current is None:
        return True
    return (
        current.get("tool") != fields["tool"]
        or current.get("summary") != fields["summary"]
        or current.get("message") != fields["message"]
    )


def _recorded_evidence_changed(current: dict[str, Any] | None, fields: dict[str, str]) -> bool:
    if current is None:
        return True
    return current.get("tool") != fields["tool"] or current.get("summary") != fields["summary"]


def _append_unique_capped(items: list[str], item: str, limit: int) -> list[str]:
    if item in items:
        return items
    return _append_capped(items, item, limit)


def _append_capped(items: list[str], item: str, limit: int) -> list[str]:
    if len(items) >= limit:
        return items
    return [*items, item]


def _append_dict_capped(items: list[dict], item: dict, limit: int) -> list[dict]:
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


def _build_pending_approval(stage_id: str, message: str) -> dict[str, Any]:
    return {
        "required": True,
        "stage_id": _safe_status_text(stage_id, ""),
        "message": _safe_status_text(message, ""),
    }


def _coerce_pending_approval(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return default_pending_approval()
    if not bool(value.get("required", False)):
        return default_pending_approval()
    stage_id = value.get("stage_id")
    message = value.get("message")
    return _build_pending_approval(
        stage_id if isinstance(stage_id, str) else "",
        message if isinstance(message, str) else "",
    )


def _coerce_optional_dict(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return dict(value)


def _coerce_recorded_evidence(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    tool = value.get("tool")
    summary = value.get("summary")
    timestamp = value.get("timestamp")
    if not isinstance(tool, str) or not isinstance(summary, str) or not isinstance(timestamp, str):
        return None
    safe_tool = _safe_status_text(tool, "")
    safe_summary = _safe_status_text(summary, "")
    safe_timestamp = _safe_status_text(timestamp, "")
    if not safe_tool or not safe_summary or not safe_timestamp:
        return None
    return {
        "tool": safe_tool,
        "summary": safe_summary,
        "timestamp": safe_timestamp,
    }


def _coerce_mcp_result(value: Any) -> dict[str, Any]:
    """Sanitize one MCP result dict — applied both on ingest and on load.

    String values are passed through _safe_status_text to strip control
    characters and enforce the length limit.  None is converted to the empty
    string so that str(None) == "None" cannot produce a false positive in gate
    evaluation.  All other non-string values are kept as-is.
    """
    if not isinstance(value, dict):
        return {}
    result: dict[str, Any] = {}
    for k, v in value.items():
        key = k if isinstance(k, str) else str(k)
        if isinstance(v, str):
            result[key] = _safe_status_text(v, "")
        elif v is None:
            result[key] = ""
        else:
            result[key] = v
    return result

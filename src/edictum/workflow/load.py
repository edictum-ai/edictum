"""Workflow YAML loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from edictum._exceptions import EdictumConfigError
from edictum.workflow.definition import (
    WorkflowApproval,
    WorkflowCheck,
    WorkflowDefinition,
    WorkflowGate,
    WorkflowMetadata,
    WorkflowStage,
)
from edictum.workflow.evaluator import compile_workflow_regex

MAX_WORKFLOW_DOCUMENT_SIZE = 1_048_576


def load_workflow(path: str | Path) -> WorkflowDefinition:
    raw = Path(path).read_bytes()
    return load_workflow_string(raw)


def load_workflow_string(content: str | bytes) -> WorkflowDefinition:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - exercised in lazy import tests elsewhere
        raise ImportError(
            "The YAML engine requires pyyaml and jsonschema. Install them with: pip install edictum[yaml]"
        ) from exc

    raw = content.encode("utf-8") if isinstance(content, str) else content
    if len(raw) > MAX_WORKFLOW_DOCUMENT_SIZE:
        raise EdictumConfigError(f"workflow: document too large ({len(raw)} bytes, max {MAX_WORKFLOW_DOCUMENT_SIZE})")

    try:
        documents = list(yaml.safe_load_all(raw))
    except yaml.YAMLError as exc:
        raise EdictumConfigError(f"workflow: parse error: {exc}") from exc

    if len(documents) != 1:
        raise EdictumConfigError("workflow: multiple YAML documents are not supported")
    data = documents[0]
    if not isinstance(data, dict):
        raise EdictumConfigError("workflow: YAML document must be a mapping")

    try:
        definition = _parse_definition(data)
        definition.validate()
    except ValueError as exc:
        raise EdictumConfigError(str(exc)) from exc
    return definition


def _parse_definition(data: dict[str, Any]) -> WorkflowDefinition:
    _reject_unknown_fields(data, {"apiVersion", "kind", "metadata", "stages"}, "workflow")
    metadata_data = _require_mapping(data.get("metadata"), "workflow metadata")
    _reject_unknown_fields(metadata_data, {"name", "description"}, "workflow metadata")

    stages_data = data.get("stages")
    if not isinstance(stages_data, list):
        raise ValueError("workflow: stages must contain at least one item")

    stages: list[WorkflowStage] = []
    for stage_data in stages_data:
        stages.append(_parse_stage(_require_mapping(stage_data, "workflow stage")))

    return WorkflowDefinition(
        api_version=str(data.get("apiVersion", "")),
        kind=str(data.get("kind", "")),
        metadata=WorkflowMetadata(
            name=str(metadata_data.get("name", "")),
            description=str(metadata_data.get("description", "")),
        ),
        stages=tuple(stages),
    )


def _parse_stage(data: dict[str, Any]) -> WorkflowStage:
    stage_id = str(data.get("id", ""))
    _reject_unknown_fields(
        data,
        {"id", "description", "entry", "tools", "checks", "exit", "approval"},
        f'stage "{stage_id or "?"}"',
    )
    approval = None
    if data.get("approval") is not None:
        approval_data = _require_mapping(data.get("approval"), f'stage "{stage_id}" approval')
        _reject_unknown_fields(approval_data, {"message"}, f'stage "{stage_id}" approval')
        approval = WorkflowApproval(message=str(approval_data.get("message", "")))

    checks: list[WorkflowCheck] = []
    for raw_check in data.get("checks") or []:
        check_data = _require_mapping(raw_check, f'stage "{stage_id}" check')
        _reject_unknown_fields(
            check_data,
            {"command_matches", "command_not_matches", "message"},
            f'stage "{stage_id}" check',
        )
        command_matches = check_data.get("command_matches")
        command_not_matches = check_data.get("command_not_matches")
        checks.append(
            WorkflowCheck(
                message=str(check_data.get("message", "")),
                command_matches=str(command_matches) if command_matches is not None else None,
                command_not_matches=str(command_not_matches) if command_not_matches is not None else None,
                command_matches_re=_compile_check_regex(
                    command_matches,
                    stage_id,
                    "command_matches",
                ),
                command_not_matches_re=_compile_check_regex(
                    command_not_matches,
                    stage_id,
                    "command_not_matches",
                ),
            )
        )

    return WorkflowStage(
        id=stage_id,
        description=str(data.get("description", "")),
        entry=tuple(_parse_gate_list(data.get("entry") or [], stage_id, "entry")),
        tools=tuple(str(tool) for tool in (data.get("tools") or [])),
        checks=tuple(checks),
        exit=tuple(_parse_gate_list(data.get("exit") or [], stage_id, "exit")),
        approval=approval,
    )


def _parse_gate_list(items: list[Any], stage_id: str, label: str) -> list[WorkflowGate]:
    gates: list[WorkflowGate] = []
    for item in items:
        gate_data = _require_mapping(item, f'stage "{stage_id}" {label} gate')
        _reject_unknown_fields(gate_data, {"condition", "message"}, f'stage "{stage_id}" {label} gate')
        gates.append(
            WorkflowGate(
                condition=str(gate_data.get("condition", "")),
                message=str(gate_data.get("message", "")),
            )
        )
    return gates


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"workflow: {label} must be a mapping")
    return value


def _reject_unknown_fields(data: dict[str, Any], allowed: set[str], label: str) -> None:
    extra = set(data) - allowed
    if extra:
        names = ", ".join(sorted(extra))
        raise ValueError(f"workflow: unexpected field(s) in {label}: {names}")


def _compile_check_regex(raw: Any, stage_id: str, field_name: str):
    if raw is None:
        return None
    pattern = str(raw)
    try:
        return compile_workflow_regex(pattern, pattern)
    except ValueError as exc:
        raise ValueError(f'workflow: stage "{stage_id}" invalid {field_name} regex "{pattern}": {exc}') from exc

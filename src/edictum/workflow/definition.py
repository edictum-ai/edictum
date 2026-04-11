"""Workflow definition types and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from edictum.envelope import _validate_tool_name

_WORKFLOW_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


@dataclass(frozen=True)
class WorkflowMetadata:
    """Workflow document identity."""

    name: str
    description: str = ""
    version: str = ""


@dataclass(frozen=True)
class WorkflowGate:
    """Declarative workflow fact check."""

    condition: str
    message: str = ""


@dataclass(frozen=True)
class WorkflowApproval:
    """Stage-boundary approval requirement."""

    message: str


@dataclass(frozen=True)
class WorkflowCheck:
    """Constraint on a call while a stage is active."""

    message: str
    command_matches: str | None = None
    command_not_matches: str | None = None
    command_matches_re: re.Pattern[str] | None = field(default=None, repr=False, compare=False)
    command_not_matches_re: re.Pattern[str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        from edictum.workflow.evaluator import compile_workflow_regex

        if self.command_matches is not None and self.command_matches_re is None:
            object.__setattr__(
                self,
                "command_matches_re",
                compile_workflow_regex(self.command_matches, self.command_matches),
            )
        if self.command_not_matches is not None and self.command_not_matches_re is None:
            object.__setattr__(
                self,
                "command_not_matches_re",
                compile_workflow_regex(self.command_not_matches, self.command_not_matches),
            )


@dataclass(frozen=True)
class WorkflowStage:
    """One linear workflow stage."""

    id: str
    description: str = ""
    entry: tuple[WorkflowGate, ...] = ()
    tools: tuple[str, ...] = ()
    checks: tuple[WorkflowCheck, ...] = ()
    exit: tuple[WorkflowGate, ...] = ()
    approval: WorkflowApproval | None = None
    terminal: bool = False


@dataclass(frozen=True)
class WorkflowDefinition:
    """Validated workflow document."""

    api_version: str
    kind: str
    metadata: WorkflowMetadata
    stages: tuple[WorkflowStage, ...]
    index: dict[str, int] = field(default_factory=dict, repr=False)

    def validate(self) -> None:
        if self.api_version != "edictum/v1":
            raise ValueError('workflow: apiVersion must be "edictum/v1"')
        if self.kind != "Workflow":
            raise ValueError('workflow: kind must be "Workflow"')
        if not _WORKFLOW_NAME_RE.match(self.metadata.name):
            raise ValueError(f'workflow: metadata.name must match "{_WORKFLOW_NAME_RE.pattern}"')
        if not self.stages:
            raise ValueError("workflow: stages must contain at least one item")

        index: dict[str, int] = {}
        for idx, stage in enumerate(self.stages):
            _validate_stage(stage)
            if stage.id in index:
                raise ValueError(f'workflow: duplicate stage id "{stage.id}"')
            index[stage.id] = idx
        object.__setattr__(self, "index", index)

    def stage_index(self, stage_id: str) -> int | None:
        return self.index.get(stage_id)

    def stage_by_id(self, stage_id: str) -> WorkflowStage | None:
        idx = self.stage_index(stage_id)
        if idx is None:
            return None
        return self.stages[idx]


def _validate_stage(stage: WorkflowStage) -> None:
    if not _WORKFLOW_NAME_RE.match(stage.id):
        raise ValueError(f'workflow: stage.id "{stage.id}" must match "{_WORKFLOW_NAME_RE.pattern}"')

    from edictum.workflow.evaluator import compile_workflow_regex, parse_condition

    for tool in stage.tools:
        try:
            _validate_tool_name(tool)
        except ValueError as exc:  # pragma: no cover - exact message delegated
            raise ValueError(f'workflow: invalid tool "{tool}" in stage "{stage.id}": {exc}') from exc

    for gate in (*stage.entry, *stage.exit):
        if not gate.condition:
            raise ValueError(f'workflow: stage "{stage.id}" gate condition must not be empty')
        try:
            parse_condition(gate.condition)
        except ValueError as exc:
            raise ValueError(f'workflow: stage "{stage.id}" invalid gate condition "{gate.condition}": {exc}') from exc

    for check in stage.checks:
        if (check.command_matches is None) == (check.command_not_matches is None):
            raise ValueError(
                f'workflow: stage "{stage.id}" checks must set exactly one of command_matches or command_not_matches'
            )
        if not check.message:
            raise ValueError(f'workflow: stage "{stage.id}" checks require message')
        if check.command_matches is not None:
            try:
                compile_workflow_regex(check.command_matches, check.command_matches)
            except ValueError as exc:
                raise ValueError(
                    f'workflow: stage "{stage.id}" invalid command_matches regex "{check.command_matches}": {exc}'
                ) from exc
        if check.command_not_matches is not None:
            try:
                compile_workflow_regex(check.command_not_matches, check.command_not_matches)
            except ValueError as exc:
                raise ValueError(
                    "workflow: stage "
                    f'"{stage.id}" invalid command_not_matches regex "{check.command_not_matches}": {exc}'
                ) from exc

    if stage.approval is not None and not stage.approval.message:
        raise ValueError(f'workflow: stage "{stage.id}" approval.message is required')

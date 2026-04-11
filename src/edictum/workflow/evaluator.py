"""Workflow gate evaluators and condition parsing."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Protocol, cast

from edictum.envelope import ToolCall
from edictum.workflow.definition import WorkflowDefinition, WorkflowGate, WorkflowStage
from edictum.workflow.result import WorkflowState

MAX_WORKFLOW_REGEX_LENGTH = 10_000
_SINGLE_STRING_ARG_RE = re.compile(r'^([a-z_]+)\("((?:[^"\\]|\\.)*)"\)$')
_OPTIONAL_ARG_RE = re.compile(r'^approval\((?:"((?:[^"\\]|\\.)*)")?\)$')
_EXEC_CONDITION_RE = re.compile(r'^exec\("((?:[^"\\]|\\.)*)"(?:,\s*exit_code=(\d+))?\)$')
_MCP_RESULT_MATCHES_RE = re.compile(r'^mcp_result_matches\("([^"\\]+)",\s*"([^"\\]+)",\s*"([^"\\]+)"\)$')


class FactEvaluator(Protocol):
    """Evaluate one workflow gate condition."""

    async def evaluate(self, req: EvaluateRequest) -> FactResult: ...


@dataclass(frozen=True)
class ParsedCondition:
    """Parsed workflow gate condition."""

    kind: str
    arg: str
    condition: str
    exit_code: int = 0
    regex: re.Pattern[str] | None = None
    extra: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvaluateRequest:
    """Input for one workflow gate evaluation."""

    definition: WorkflowDefinition
    stage: WorkflowStage
    gate: WorkflowGate
    parsed: ParsedCondition
    state: WorkflowState
    call: ToolCall


@dataclass
class FactResult:
    """One gate evaluation outcome."""

    passed: bool
    evidence: str
    kind: str
    condition: str
    message: str
    stage_id: str
    workflow: str
    extra_audit: dict[str, object] = field(default_factory=dict)


class StageCompleteEvaluator:
    async def evaluate(self, req: EvaluateRequest) -> FactResult:
        parsed = req.parsed
        return FactResult(
            passed=req.state.completed(parsed.arg),
            evidence=parsed.arg,
            kind="stage_complete",
            condition=parsed.condition,
            message=req.gate.message,
            stage_id=req.stage.id,
            workflow=req.definition.metadata.name,
        )


class FileReadEvaluator:
    async def evaluate(self, req: EvaluateRequest) -> FactResult:
        parsed = req.parsed
        return FactResult(
            passed=parsed.arg in req.state.evidence.reads,
            evidence=parsed.arg,
            kind="file_read",
            condition=parsed.condition,
            message=req.gate.message,
            stage_id=req.stage.id,
            workflow=req.definition.metadata.name,
        )


class ApprovalEvaluator:
    async def evaluate(self, req: EvaluateRequest) -> FactResult:
        parsed = req.parsed
        stage_id = parsed.arg or req.stage.id
        evidence = req.state.approvals.get(stage_id, "")
        return FactResult(
            passed=evidence == "approved",
            evidence=evidence,
            kind="approval",
            condition=parsed.condition,
            message=req.gate.message,
            stage_id=req.stage.id,
            workflow=req.definition.metadata.name,
        )


class McpResultMatchesEvaluator:
    async def evaluate(self, req: EvaluateRequest) -> FactResult:
        tool, field_name, value = req.parsed.extra
        mcp_results = req.state.evidence.mcp_results
        results_for_tool = mcp_results.get(tool, [])
        passed = any(field_name in result and str(result[field_name]) == value for result in results_for_tool)
        return FactResult(
            passed=passed,
            evidence=tool,
            kind="mcp_result_matches",
            condition=req.parsed.condition,
            message=req.gate.message,
            stage_id=req.stage.id,
            workflow=req.definition.metadata.name,
        )


class CommandEvaluator:
    async def evaluate(self, req: EvaluateRequest) -> FactResult:
        parsed = req.parsed
        commands = req.state.evidence.stage_calls.get(req.stage.id, [])
        passed = parsed.kind == "command_not_matches"
        for command in commands:
            matched = bool(parsed.regex and parsed.regex.search(command))
            if parsed.kind == "command_matches" and matched:
                passed = True
                break
            if parsed.kind == "command_not_matches" and matched:
                passed = False
                break
        return FactResult(
            passed=passed,
            evidence=join_evidence(commands),
            kind=parsed.kind,
            condition=parsed.condition,
            message=req.gate.message,
            stage_id=req.stage.id,
            workflow=req.definition.metadata.name,
        )


def uses_exec_condition(definition) -> bool:
    for stage in definition.stages:
        for gate in (*stage.entry, *stage.exit):
            if parse_condition(gate.condition).kind == "exec":
                return True
    return False


def parse_condition(raw: str) -> ParsedCondition:
    if raw.startswith("stage_complete("):
        arg = _parse_single_string_arg(raw, "stage_complete")
        return ParsedCondition(kind="stage_complete", arg=arg, condition=raw)
    if raw.startswith("file_read("):
        arg = _parse_single_string_arg(raw, "file_read")
        return ParsedCondition(kind="file_read", arg=arg, condition=raw)
    if raw.startswith("approval("):
        arg = _parse_optional_string_arg(raw, "approval")
        return ParsedCondition(kind="approval", arg=arg, condition=raw)
    if raw.startswith("command_matches("):
        arg = _parse_single_string_arg(raw, "command_matches")
        return ParsedCondition(
            kind="command_matches",
            arg=arg,
            regex=compile_workflow_regex(arg, raw),
            condition=raw,
        )
    if raw.startswith("command_not_matches("):
        arg = _parse_single_string_arg(raw, "command_not_matches")
        return ParsedCondition(
            kind="command_not_matches",
            arg=arg,
            regex=compile_workflow_regex(arg, raw),
            condition=raw,
        )
    if raw.startswith("exec("):
        match = _EXEC_CONDITION_RE.fullmatch(raw)
        if match is None:
            raise ValueError(f'workflow: unsupported exec condition "{raw}"')
        arg = _unquote(match.group(1))
        exit_code = int(match.group(2) or "0")
        return ParsedCondition(kind="exec", arg=arg, exit_code=exit_code, condition=raw)
    if raw.startswith("mcp_result_matches("):
        match = _MCP_RESULT_MATCHES_RE.fullmatch(raw)
        if match is None:
            raise ValueError(f'workflow: unsupported mcp_result_matches condition "{raw}"')
        tool, field_name, value = match.group(1), match.group(2), match.group(3)
        return ParsedCondition(
            kind="mcp_result_matches",
            arg=tool,
            extra=(tool, field_name, value),
            condition=raw,
        )
    raise ValueError(f'workflow: unsupported condition "{raw}"')


def compile_workflow_regex(pattern: str, context: str) -> re.Pattern[str]:
    if len(pattern) > MAX_WORKFLOW_REGEX_LENGTH:
        raise ValueError(f'workflow: regex in "{context}" exceeds {MAX_WORKFLOW_REGEX_LENGTH} characters')
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ValueError(f'workflow: invalid regex in "{context}": {exc}') from exc


def gate_record(result: FactResult, passed: bool) -> dict[str, object]:
    metadata: dict[str, object] = {
        "workflow_name": result.workflow,
        "stage_id": result.stage_id,
        "gate_kind": result.kind,
        "gate_condition": result.condition,
        "gate_passed": passed,
        "gate_evidence": result.evidence,
    }
    metadata.update(result.extra_audit)
    return {
        "name": f"{result.workflow}:{result.stage_id}:{result.kind}",
        "type": "workflow_gate",
        "passed": passed,
        "message": result.message,
        "metadata": metadata,
    }


def join_evidence(items: list[str]) -> str:
    return " | ".join(items)


def _parse_single_string_arg(raw: str, fn: str) -> str:
    match = _SINGLE_STRING_ARG_RE.fullmatch(raw)
    if match is None or match.group(1) != fn:
        raise ValueError(f'workflow: unsupported {fn} condition "{raw}"')
    return _unquote(match.group(2))


def _parse_optional_string_arg(raw: str, fn: str) -> str:
    match = _OPTIONAL_ARG_RE.fullmatch(raw)
    if match is None or fn != "approval":
        raise ValueError(f'workflow: unsupported {fn} condition "{raw}"')
    if not match.group(1):
        return ""
    return _unquote(match.group(1))


def _unquote(value: str) -> str:
    result = cast(str, ast.literal_eval(f'"{value}"'))
    for char in result:
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise ValueError("workflow: condition arguments must not contain control characters")
    return result

"""Evaluation result dataclasses for dry-run rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleResult:
    """Result of evaluating a single rule."""

    rule_id: str
    contract_type: str  # "precondition" | "postcondition" | "sandbox"
    passed: bool
    message: str | None = None
    tags: list[str] = field(default_factory=list)
    observed: bool = False
    action: str = "warn"
    policy_error: bool = False


@dataclass(frozen=True)
class EvaluationResult:
    """Result of dry-run evaluation of a tool call against rules."""

    decision: str  # "allow" | "block" | "warn"
    tool_name: str
    rules: list[RuleResult] = field(default_factory=list)
    deny_reasons: list[str] = field(default_factory=list)
    warn_reasons: list[str] = field(default_factory=list)
    contracts_evaluated: int = 0
    policy_error: bool = False

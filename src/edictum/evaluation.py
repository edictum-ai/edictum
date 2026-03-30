"""Evaluation result dataclasses for dry-run rule evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_LEGACY_RESULT_NAME = "Contract" + "Result"
_LEGACY_ID_FIELD = "contract" + "_id"
_LEGACY_TYPE_FIELD = "contract" + "_type"


@dataclass(frozen=True, init=False)
class RuleResult:
    """Result of evaluating a single rule."""

    rule_id: str
    rule_type: str  # "precondition" | "postcondition" | "sandbox"
    passed: bool
    message: str | None = None
    tags: list[str] = field(default_factory=list)
    observed: bool = False
    action: str = "warn"
    policy_error: bool = False

    def __init__(
        self,
        *,
        rule_id: str | None = None,
        rule_type: str | None = None,
        passed: bool,
        message: str | None = None,
        tags: list[str] | None = None,
        observed: bool = False,
        action: str = "warn",
        policy_error: bool = False,
        **kwargs: Any,
    ) -> None:
        legacy_id = kwargs.pop(_LEGACY_ID_FIELD, None)
        legacy_type = kwargs.pop(_LEGACY_TYPE_FIELD, None)
        if kwargs:
            unexpected = ", ".join(sorted(kwargs))
            raise TypeError(f"Unexpected RuleResult kwargs: {unexpected}")
        resolved_id = rule_id if rule_id is not None else legacy_id
        resolved_type = rule_type if rule_type is not None else legacy_type
        if resolved_id is None or resolved_type is None:
            raise TypeError("RuleResult requires rule_id and rule_type")

        object.__setattr__(self, "rule_id", resolved_id)
        object.__setattr__(self, "rule_type", resolved_type)
        object.__setattr__(self, "passed", passed)
        object.__setattr__(self, "message", message)
        object.__setattr__(self, "tags", [] if tags is None else tags)
        object.__setattr__(self, "observed", observed)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "policy_error", policy_error)

    def __getattr__(self, name: str) -> Any:
        if name == _LEGACY_ID_FIELD:
            return self.rule_id
        if name == _LEGACY_TYPE_FIELD:
            return self.rule_type
        raise AttributeError(name)


@dataclass(frozen=True)
class EvaluationResult:
    """Result of dry-run evaluation of a tool call against rules."""

    decision: str  # "allow" | "block" | "warn"
    tool_name: str
    rules: list[RuleResult] = field(default_factory=list)
    block_reasons: list[str] = field(default_factory=list)
    warn_reasons: list[str] = field(default_factory=list)
    rules_evaluated: int = 0
    policy_error: bool = False


globals()[_LEGACY_RESULT_NAME] = RuleResult

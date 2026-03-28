"""Condition Evaluator — resolve selectors and apply operators against ToolCall."""

from __future__ import annotations

import logging
import re
from typing import Any

from edictum.envelope import ToolCall

logger = logging.getLogger(__name__)

# Sentinel for "field not found"
_MISSING = object()

# Cap regex input to prevent catastrophic backtracking DoS
MAX_REGEX_INPUT = 10_000

# Built-in selector prefixes — custom selectors must not use these
BUILTIN_SELECTOR_PREFIXES: frozenset[str] = frozenset(
    {"environment", "tool", "args", "principal", "output", "env", "metadata"}
)


def evaluate_expression(
    expr: dict,
    tool_call: ToolCall,
    output_text: str | None = None,
    *,
    custom_operators: dict[str, Any] | None = None,
    custom_selectors: dict[str, Any] | None = None,
) -> bool | _PolicyError:
    """Evaluate a boolean expression tree against an tool_call.

    Returns True if the expression matches, False if it does not.
    Returns a _PolicyError instance if a type mismatch or evaluation
    error occurs (caller should treat as block/warn + policy_error).

    Missing fields always evaluate to False (rule doesn't fire).
    """
    if "all" in expr:
        return _eval_all(expr["all"], tool_call, output_text, custom_operators, custom_selectors)
    if "any" in expr:
        return _eval_any(expr["any"], tool_call, output_text, custom_operators, custom_selectors)
    if "not" in expr:
        return _eval_not(expr["not"], tool_call, output_text, custom_operators, custom_selectors)

    # Leaf node: exactly one selector key
    return _eval_leaf(expr, tool_call, output_text, custom_operators, custom_selectors)


class _PolicyError:
    """Sentinel indicating a type mismatch or evaluation error."""

    __slots__ = ("message",)

    def __init__(self, message: str) -> None:
        self.message = message

    def __bool__(self) -> bool:
        return True  # Errors trigger the rule (fail-closed)


def _eval_all(
    exprs: list[dict],
    tool_call: ToolCall,
    output_text: str | None,
    custom_operators: dict[str, Any] | None,
    custom_selectors: dict[str, Any] | None,
) -> bool | _PolicyError:
    for expr in exprs:
        result = evaluate_expression(
            expr, tool_call, output_text, custom_operators=custom_operators, custom_selectors=custom_selectors
        )
        if isinstance(result, _PolicyError):
            return result
        if not result:
            return False
    return True


def _eval_any(
    exprs: list[dict],
    tool_call: ToolCall,
    output_text: str | None,
    custom_operators: dict[str, Any] | None,
    custom_selectors: dict[str, Any] | None,
) -> bool | _PolicyError:
    for expr in exprs:
        result = evaluate_expression(
            expr, tool_call, output_text, custom_operators=custom_operators, custom_selectors=custom_selectors
        )
        if isinstance(result, _PolicyError):
            return result
        if result:
            return True
    return False


def _eval_not(
    expr: dict,
    tool_call: ToolCall,
    output_text: str | None,
    custom_operators: dict[str, Any] | None,
    custom_selectors: dict[str, Any] | None,
) -> bool | _PolicyError:
    result = evaluate_expression(
        expr, tool_call, output_text, custom_operators=custom_operators, custom_selectors=custom_selectors
    )
    if isinstance(result, _PolicyError):
        return result
    return not result


def _eval_leaf(
    leaf: dict,
    tool_call: ToolCall,
    output_text: str | None,
    custom_operators: dict[str, Any] | None,
    custom_selectors: dict[str, Any] | None,
) -> bool | _PolicyError:
    # Exactly one key in the leaf
    selector = next(iter(leaf))
    operator_block = leaf[selector]

    # Resolve the field value
    value = _resolve_selector(selector, tool_call, output_text, custom_selectors)

    # Apply the single operator
    op_name = next(iter(operator_block))
    op_value = operator_block[op_name]

    return _apply_operator(op_name, value, op_value, selector, custom_operators)


def _coerce_env_value(raw: str) -> str | bool | int | float:
    """Coerce an env var string to a typed value for operator comparison."""
    low = raw.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _resolve_selector(
    selector: str,
    tool_call: ToolCall,
    output_text: str | None,
    custom_selectors: dict[str, Any] | None = None,
) -> Any:
    """Resolve a dotted selector path to a value from the tool_call.

    Returns _MISSING if the field is not found at any level.
    """
    if selector == "environment":
        return tool_call.environment

    if selector == "tool.name":
        return tool_call.tool_name

    if selector.startswith("args."):
        return _resolve_nested(selector[5:], tool_call.args)

    if selector.startswith("principal."):
        if tool_call.principal is None:
            return _MISSING
        rest = selector[10:]
        if rest == "user_id":
            return tool_call.principal.user_id
        if rest == "service_id":
            return tool_call.principal.service_id
        if rest == "org_id":
            return tool_call.principal.org_id
        if rest == "role":
            return tool_call.principal.role
        if rest == "ticket_ref":
            return tool_call.principal.ticket_ref
        if rest.startswith("claims."):
            return _resolve_nested(rest[7:], tool_call.principal.claims)
        return _MISSING

    if selector == "output.text":
        if output_text is None:
            return _MISSING
        return output_text

    if selector.startswith("env."):
        import os

        var_name = selector[4:]
        raw = os.environ.get(var_name)
        if raw is None:
            return _MISSING
        return _coerce_env_value(raw)

    if selector.startswith("metadata."):
        return _resolve_nested(selector[9:], tool_call.metadata)

    # Custom selectors: match prefix before first dot
    if custom_selectors:
        dot_pos = selector.find(".")
        if dot_pos > 0:
            prefix = selector[:dot_pos]
            if prefix in custom_selectors:
                resolver = custom_selectors[prefix]
                data = resolver(tool_call)
                rest = selector[dot_pos + 1 :]
                return _resolve_nested(rest, data)

    return _MISSING


def _resolve_nested(path: str, data: Any) -> Any:
    """Resolve a dotted path through nested dicts.

    Returns _MISSING if any intermediate key is absent or not a dict.
    """
    parts = path.split(".")
    current = data
    for part in parts:
        if not isinstance(current, dict):
            return _MISSING
        if part not in current:
            return _MISSING
        current = current[part]
    return current


def _apply_operator(
    op: str,
    field_value: Any,
    op_value: Any,
    selector: str,
    custom_operators: dict[str, Any] | None = None,
) -> bool | _PolicyError:
    """Apply a single operator to a resolved field value."""
    # exists is special — works on _MISSING
    if op == "exists":
        is_present = field_value is not _MISSING and field_value is not None
        return is_present == op_value

    # All other operators: missing field → false
    if field_value is _MISSING or field_value is None:
        return False

    try:
        if op in _OPERATORS:
            return _OPERATORS[op](field_value, op_value)
        if custom_operators and op in custom_operators:
            return bool(custom_operators[op](field_value, op_value))
        return _PolicyError(f"Unknown operator: '{op}'")
    except TypeError:
        return _PolicyError(
            f"Type mismatch: operator '{op}' cannot be applied to "
            f"selector '{selector}' value {type(field_value).__name__}"
        )


# --- Operator implementations ---


def _op_equals(field_value: Any, op_value: Any) -> bool:
    return field_value == op_value


def _op_not_equals(field_value: Any, op_value: Any) -> bool:
    return field_value != op_value


def _op_in(field_value: Any, op_value: list) -> bool:
    return field_value in op_value


def _op_not_in(field_value: Any, op_value: list) -> bool:
    return field_value not in op_value


def _op_contains(field_value: Any, op_value: str) -> bool:
    if not isinstance(field_value, str):
        raise TypeError
    return op_value in field_value


def _op_contains_any(field_value: Any, op_value: list[str]) -> bool:
    if not isinstance(field_value, str):
        raise TypeError
    return any(v in field_value for v in op_value)


def _op_starts_with(field_value: Any, op_value: str) -> bool:
    if not isinstance(field_value, str):
        raise TypeError
    return field_value.startswith(op_value)


def _op_ends_with(field_value: Any, op_value: str) -> bool:
    if not isinstance(field_value, str):
        raise TypeError
    return field_value.endswith(op_value)


def _op_matches(field_value: Any, op_value: str | re.Pattern) -> bool:
    if not isinstance(field_value, str):
        raise TypeError
    truncated = field_value[:MAX_REGEX_INPUT]
    if len(field_value) > MAX_REGEX_INPUT:
        logger.warning("Regex input truncated from %d to %d chars", len(field_value), MAX_REGEX_INPUT)
    if isinstance(op_value, re.Pattern):
        return bool(op_value.search(truncated))
    return bool(re.search(op_value, truncated))


def _op_matches_any(field_value: Any, op_value: list[str | re.Pattern]) -> bool:
    if not isinstance(field_value, str):
        raise TypeError
    truncated = field_value[:MAX_REGEX_INPUT]
    if len(field_value) > MAX_REGEX_INPUT:
        logger.warning("Regex input truncated from %d to %d chars", len(field_value), MAX_REGEX_INPUT)
    return any(p.search(truncated) if isinstance(p, re.Pattern) else re.search(p, truncated) for p in op_value)


def _op_gt(field_value: Any, op_value: float | int) -> bool:
    if not isinstance(field_value, int | float):
        raise TypeError
    return field_value > op_value


def _op_gte(field_value: Any, op_value: float | int) -> bool:
    if not isinstance(field_value, int | float):
        raise TypeError
    return field_value >= op_value


def _op_lt(field_value: Any, op_value: float | int) -> bool:
    if not isinstance(field_value, int | float):
        raise TypeError
    return field_value < op_value


def _op_lte(field_value: Any, op_value: float | int) -> bool:
    if not isinstance(field_value, int | float):
        raise TypeError
    return field_value <= op_value


_OPERATORS: dict[str, Any] = {
    "equals": _op_equals,
    "not_equals": _op_not_equals,
    "in": _op_in,
    "not_in": _op_not_in,
    "contains": _op_contains,
    "contains_any": _op_contains_any,
    "starts_with": _op_starts_with,
    "ends_with": _op_ends_with,
    "matches": _op_matches,
    "matches_any": _op_matches_any,
    "gt": _op_gt,
    "gte": _op_gte,
    "lt": _op_lt,
    "lte": _op_lte,
}

BUILTIN_OPERATOR_NAMES: frozenset[str] = frozenset(_OPERATORS) | frozenset({"exists"})

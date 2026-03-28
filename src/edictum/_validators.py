"""Custom operator and selector validation for YAML rules."""

from __future__ import annotations

from typing import Any

from edictum._exceptions import EdictumConfigError


def validate_custom_operators(custom_operators: dict[str, Any]) -> None:
    """Validate custom operator names don't clash with built-in operators."""
    from edictum.yaml_engine.evaluator import BUILTIN_OPERATOR_NAMES

    clashes = set(custom_operators) & BUILTIN_OPERATOR_NAMES
    if clashes:
        raise EdictumConfigError(f"Custom operator names clash with built-in operators: {sorted(clashes)}")
    for name, fn in custom_operators.items():
        if not callable(fn):
            raise EdictumConfigError(f"Custom operator '{name}' is not callable")


def validate_custom_selectors(custom_selectors: dict[str, Any]) -> None:
    """Validate custom selector prefixes don't clash with built-in selectors."""
    from edictum.yaml_engine.evaluator import BUILTIN_SELECTOR_PREFIXES

    clashes = set(custom_selectors) & BUILTIN_SELECTOR_PREFIXES
    if clashes:
        raise EdictumConfigError(f"Custom selector prefixes clash with built-in selectors: {sorted(clashes)}")
    for name, fn in custom_selectors.items():
        if not callable(fn):
            raise EdictumConfigError(f"Custom selector '{name}' is not callable")

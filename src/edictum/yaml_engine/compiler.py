"""Compiler — convert parsed YAML contracts into contract callables and OperationLimits."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from edictum.contracts import Verdict
from edictum.envelope import ToolEnvelope
from edictum.limits import OperationLimits
from edictum.yaml_engine.evaluator import BUILTIN_OPERATOR_NAMES, _PolicyError, evaluate_expression

# Placeholder pattern for message templating: {selector}
_PLACEHOLDER_RE = re.compile(r"\{([^}]+)\}")
_PLACEHOLDER_CAP = 200


def _validate_operators(bundle: dict, custom_operators: dict[str, Any] | None) -> None:
    """Validate that all operators used in the bundle are known (built-in or custom)."""
    known = BUILTIN_OPERATOR_NAMES | frozenset(custom_operators or {})
    for contract in bundle.get("contracts", []):
        when = contract.get("when")
        if when:
            _validate_expression_operators(when, known, contract["id"])


def _validate_expression_operators(expr: dict | Any, known: frozenset[str], contract_id: str) -> None:
    """Recursively validate operator names in an expression tree."""
    if not isinstance(expr, dict):
        return

    if "all" in expr:
        for sub in expr["all"]:
            _validate_expression_operators(sub, known, contract_id)
        return
    if "any" in expr:
        for sub in expr["any"]:
            _validate_expression_operators(sub, known, contract_id)
        return
    if "not" in expr:
        _validate_expression_operators(expr["not"], known, contract_id)
        return

    # Leaf node: selector -> operator
    for _selector, operator in expr.items():
        if isinstance(operator, dict):
            for op_name in operator:
                if op_name not in known:
                    from edictum import EdictumConfigError

                    raise EdictumConfigError(f"Contract '{contract_id}': unknown operator '{op_name}'")


@dataclass(frozen=True)
class CompiledBundle:
    """Result of compiling a YAML contract bundle."""

    preconditions: list = field(default_factory=list)
    postconditions: list = field(default_factory=list)
    session_contracts: list = field(default_factory=list)
    limits: OperationLimits = field(default_factory=OperationLimits)
    default_mode: str = "enforce"
    tools: dict[str, dict] = field(default_factory=dict)


def compile_contracts(
    bundle: dict,
    *,
    custom_operators: dict[str, Any] | None = None,
    custom_selectors: dict[str, Any] | None = None,
) -> CompiledBundle:
    """Compile a validated YAML bundle into contract objects.

    Args:
        bundle: A validated bundle dict (output of load_bundle).
        custom_operators: Optional mapping of operator names to callables.
            Each callable receives ``(field_value, operator_value)`` and
            returns ``bool``.
        custom_selectors: Optional mapping of selector prefixes to resolver
            callables. Each callable receives a ``ToolEnvelope`` and returns
            a ``dict`` that is searched via dotted-path resolution.

    Returns:
        CompiledBundle with preconditions, postconditions, session_contracts,
        and merged OperationLimits.
    """
    _validate_operators(bundle, custom_operators)

    default_mode = bundle["defaults"]["mode"]
    preconditions: list = []
    postconditions: list = []
    session_contracts: list = []
    limits = OperationLimits()

    for contract in bundle.get("contracts", []):
        # Skip disabled contracts
        if not contract.get("enabled", True):
            continue

        contract_type = contract["type"]
        contract_mode = contract.get("mode", default_mode)

        if contract_type == "pre":
            fn = _compile_pre(contract, contract_mode, custom_operators, custom_selectors)
            preconditions.append(fn)
        elif contract_type == "post":
            fn = _compile_post(contract, contract_mode, custom_operators, custom_selectors)
            postconditions.append(fn)
        elif contract_type == "session":
            is_shadow = contract.get("_shadow", False)
            if not is_shadow:
                limits = _merge_session_limits(contract, limits)
            fn = _compile_session(contract, contract_mode, limits)
            session_contracts.append(fn)

    tools = bundle.get("tools", {})

    return CompiledBundle(
        preconditions=preconditions,
        postconditions=postconditions,
        session_contracts=session_contracts,
        limits=limits,
        default_mode=default_mode,
        tools=tools,
    )


def _precompile_regexes(expr: dict | Any) -> dict | Any:
    """Recursively walk an expression tree and compile regex patterns.

    Replaces string values under ``matches`` and ``matches_any`` with
    pre-compiled ``re.Pattern`` objects so the evaluator never recompiles
    on every call.
    """
    if not isinstance(expr, dict):
        return expr

    if "all" in expr:
        return {"all": [_precompile_regexes(sub) for sub in expr["all"]]}
    if "any" in expr:
        return {"any": [_precompile_regexes(sub) for sub in expr["any"]]}
    if "not" in expr:
        return {"not": _precompile_regexes(expr["not"])}

    # Leaf node: selector -> operator
    compiled: dict = {}
    for selector, operator in expr.items():
        if not isinstance(operator, dict):
            compiled[selector] = operator
            continue
        new_op = dict(operator)
        if "matches" in new_op:
            new_op["matches"] = re.compile(new_op["matches"])
        if "matches_any" in new_op:
            new_op["matches_any"] = [re.compile(p) for p in new_op["matches_any"]]
        compiled[selector] = new_op
    return compiled


def _compile_pre(
    contract: dict,
    mode: str,
    custom_operators: dict[str, Any] | None = None,
    custom_selectors: dict[str, Any] | None = None,
) -> Any:
    """Compile a pre-contract into a precondition callable."""
    contract_id = contract["id"]
    tool = contract["tool"]
    when_expr = _precompile_regexes(contract["when"])
    then = contract["then"]
    message_template = then["message"]
    tags = then.get("tags", [])
    then_metadata = then.get("metadata", {})

    def precondition_fn(envelope: ToolEnvelope) -> Verdict:
        try:
            result = evaluate_expression(
                when_expr, envelope, custom_operators=custom_operators, custom_selectors=custom_selectors
            )
        except Exception as exc:
            # Fail-closed: evaluation error triggers the contract
            msg = _expand_message(message_template, envelope, custom_selectors=custom_selectors)
            return Verdict.fail(
                msg,
                tags=tags,
                policy_error=True,
                error_detail=str(exc),
                **then_metadata,
            )

        if isinstance(result, _PolicyError):
            msg = _expand_message(message_template, envelope, custom_selectors=custom_selectors)
            return Verdict.fail(msg, tags=tags, policy_error=True, **then_metadata)

        if result:
            msg = _expand_message(message_template, envelope, custom_selectors=custom_selectors)
            return Verdict.fail(msg, tags=tags, **then_metadata)

        return Verdict.pass_()

    # Stamp metadata so Edictum can filter/route
    precondition_fn.__name__ = contract_id
    precondition_fn._edictum_type = "precondition"
    precondition_fn._edictum_tool = tool
    precondition_fn._edictum_when = None  # filtering done inside
    precondition_fn._edictum_mode = mode
    precondition_fn._edictum_id = contract_id
    precondition_fn._edictum_source = "yaml_precondition"
    precondition_fn._edictum_effect = then.get("effect", "deny")
    precondition_fn._edictum_timeout = then.get("timeout", 300)
    precondition_fn._edictum_timeout_effect = then.get("timeout_effect", "deny")
    if contract.get("_shadow"):
        precondition_fn._edictum_shadow = True

    return precondition_fn


def _extract_output_patterns(expr: dict | Any) -> list[re.Pattern]:
    """Walk an expression tree and collect regex patterns from output.text leaves.

    Returns a flat list of compiled ``re.Pattern`` objects found under
    ``matches`` or ``matches_any`` operators where the selector is
    ``output.text``.  By the time this runs, ``_precompile_regexes``
    has already converted string patterns to ``re.Pattern``.
    """
    if not isinstance(expr, dict):
        return []

    if "all" in expr:
        patterns: list[re.Pattern] = []
        for sub in expr["all"]:
            patterns.extend(_extract_output_patterns(sub))
        return patterns
    if "any" in expr:
        patterns = []
        for sub in expr["any"]:
            patterns.extend(_extract_output_patterns(sub))
        return patterns
    if "not" in expr:
        return _extract_output_patterns(expr["not"])

    # Leaf node
    collected: list[re.Pattern] = []
    for selector, operator in expr.items():
        if selector != "output.text" or not isinstance(operator, dict):
            continue
        if "matches" in operator and isinstance(operator["matches"], re.Pattern):
            collected.append(operator["matches"])
        if "matches_any" in operator:
            for p in operator["matches_any"]:
                if isinstance(p, re.Pattern):
                    collected.append(p)
    return collected


def _compile_post(
    contract: dict,
    mode: str,
    custom_operators: dict[str, Any] | None = None,
    custom_selectors: dict[str, Any] | None = None,
) -> Any:
    """Compile a post-contract into a postcondition callable."""
    contract_id = contract["id"]
    tool = contract["tool"]
    when_expr = _precompile_regexes(contract["when"])
    then = contract["then"]
    effect = then.get("effect", "warn")
    message_template = then["message"]
    tags = then.get("tags", [])
    then_metadata = then.get("metadata", {})

    def postcondition_fn(envelope: ToolEnvelope, response: Any) -> Verdict:
        output_text = str(response) if response is not None else None
        try:
            result = evaluate_expression(
                when_expr,
                envelope,
                output_text=output_text,
                custom_operators=custom_operators,
                custom_selectors=custom_selectors,
            )
        except Exception as exc:
            msg = _expand_message(
                message_template, envelope, output_text=output_text, custom_selectors=custom_selectors
            )
            return Verdict.fail(
                msg,
                tags=tags,
                policy_error=True,
                error_detail=str(exc),
                **then_metadata,
            )

        if isinstance(result, _PolicyError):
            msg = _expand_message(
                message_template, envelope, output_text=output_text, custom_selectors=custom_selectors
            )
            return Verdict.fail(msg, tags=tags, policy_error=True, **then_metadata)

        if result:
            msg = _expand_message(
                message_template, envelope, output_text=output_text, custom_selectors=custom_selectors
            )
            return Verdict.fail(msg, tags=tags, **then_metadata)

        return Verdict.pass_()

    postcondition_fn.__name__ = contract_id
    postcondition_fn._edictum_type = "postcondition"
    postcondition_fn._edictum_tool = tool
    postcondition_fn._edictum_when = None
    postcondition_fn._edictum_mode = mode
    postcondition_fn._edictum_id = contract_id
    postcondition_fn._edictum_source = "yaml_postcondition"
    postcondition_fn._edictum_effect = effect
    postcondition_fn._edictum_redact_patterns = _extract_output_patterns(when_expr)
    if contract.get("_shadow"):
        postcondition_fn._edictum_shadow = True

    return postcondition_fn


def _compile_session(contract: dict, mode: str, limits: OperationLimits) -> Any:
    """Compile a session contract into a session_contract callable."""
    contract_id = contract["id"]
    then = contract["then"]
    message_template = then["message"]
    tags = then.get("tags", [])
    then_metadata = then.get("metadata", {})

    async def session_contract_fn(session: Any) -> Verdict:
        from edictum.session import Session as _Session

        if isinstance(session, _Session):
            exec_count = await session.execution_count()
            if exec_count >= limits.max_tool_calls:
                return Verdict.fail(message_template, tags=tags, **then_metadata)
            attempt_count = await session.attempt_count()
            if attempt_count >= limits.max_attempts:
                return Verdict.fail(message_template, tags=tags, **then_metadata)
        return Verdict.pass_()

    session_contract_fn.__name__ = contract_id
    session_contract_fn._edictum_type = "session_contract"
    session_contract_fn._edictum_mode = mode
    session_contract_fn._edictum_id = contract_id
    session_contract_fn._edictum_message = message_template
    session_contract_fn._edictum_tags = tags
    session_contract_fn._edictum_then_metadata = then_metadata
    session_contract_fn._edictum_source = "yaml_session"
    if contract.get("_shadow"):
        session_contract_fn._edictum_shadow = True

    return session_contract_fn


def _merge_session_limits(contract: dict, existing: OperationLimits) -> OperationLimits:
    """Merge session contract limits into existing OperationLimits.

    Picks the more restrictive value (lower) for each limit.
    """
    session_limits = contract["limits"]

    max_tool_calls = existing.max_tool_calls
    max_attempts = existing.max_attempts
    max_calls_per_tool = dict(existing.max_calls_per_tool)

    if "max_tool_calls" in session_limits:
        max_tool_calls = min(max_tool_calls, session_limits["max_tool_calls"])

    if "max_attempts" in session_limits:
        max_attempts = min(max_attempts, session_limits["max_attempts"])

    if "max_calls_per_tool" in session_limits:
        for tool, limit in session_limits["max_calls_per_tool"].items():
            if tool in max_calls_per_tool:
                max_calls_per_tool[tool] = min(max_calls_per_tool[tool], limit)
            else:
                max_calls_per_tool[tool] = limit

    return OperationLimits(
        max_attempts=max_attempts,
        max_tool_calls=max_tool_calls,
        max_calls_per_tool=max_calls_per_tool,
    )


def _expand_message(
    template: str,
    envelope: ToolEnvelope,
    output_text: str | None = None,
    *,
    custom_selectors: dict[str, Any] | None = None,
) -> str:
    """Expand {placeholder} tokens in a message template.

    Missing placeholders are kept as-is. Each expansion is capped at 200 chars.
    Values that look like secrets are redacted.
    """
    from edictum.audit import RedactionPolicy
    from edictum.yaml_engine.evaluator import _MISSING, _resolve_selector

    _redaction = RedactionPolicy()

    def replacer(match: re.Match) -> str:
        selector = match.group(1)
        value = _resolve_selector(selector, envelope, output_text, custom_selectors)
        if value is _MISSING or value is None:
            return match.group(0)  # Keep placeholder as-is
        text = str(value)
        if _redaction._looks_like_secret(text):
            text = "[REDACTED]"
        if len(text) > _PLACEHOLDER_CAP:
            text = text[: _PLACEHOLDER_CAP - 3] + "..."
        return text

    return _PLACEHOLDER_RE.sub(replacer, template)

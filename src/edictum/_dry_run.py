"""Dry-run evaluation logic for Edictum.evaluate() and evaluate_batch()."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from edictum.envelope import Principal, create_envelope
from edictum.evaluation import EvaluationResult, RuleResult

if TYPE_CHECKING:
    from edictum._guard import Edictum


def _evaluate(
    self: Edictum,
    tool_name: str,
    args: dict[str, Any],
    *,
    principal: Principal | None = None,
    output: str | None = None,
    environment: str | None = None,
) -> EvaluationResult:
    """Dry-run evaluation of a tool call against all matching rules.

    Unlike run(), this never executes the tool and evaluates all
    matching rules exhaustively (no short-circuit on first block).
    Session rules are skipped (no session state in dry-run).
    """
    env = environment or self.environment
    tool_call = create_envelope(
        tool_name=tool_name,
        tool_input=args,
        environment=env,
        principal=principal,
        registry=self.tool_registry,
    )

    rules: list[RuleResult] = []
    deny_reasons: list[str] = []
    warn_reasons: list[str] = []

    # Evaluate all matching preconditions (exhaustive, no short-circuit)
    for rule in self.get_preconditions(tool_call):
        rule_id = getattr(rule, "_edictum_id", None) or getattr(rule, "__name__", "unknown")
        try:
            decision = rule(tool_call)
        except Exception as exc:
            contract_result = RuleResult(
                rule_id=rule_id,
                contract_type="precondition",
                passed=False,
                message=f"Precondition error: {exc}",
                policy_error=True,
            )
            rules.append(contract_result)
            deny_reasons.append(contract_result.message)
            continue

        tags = decision.metadata.get("tags", []) if decision.metadata else []
        is_observed = getattr(rule, "_edictum_mode", None) == "observe" and not decision.passed
        pe = decision.metadata.get("policy_error", False) if decision.metadata else False

        contract_result = RuleResult(
            rule_id=rule_id,
            contract_type="precondition",
            passed=decision.passed,
            message=decision.message,
            tags=tags,
            observed=is_observed,
            policy_error=pe,
        )
        rules.append(contract_result)

        if not decision.passed and not is_observed:
            deny_reasons.append(decision.message or "")

    # Evaluate sandbox rules (exhaustive, no short-circuit)
    for rule in self.get_sandbox_contracts(tool_call):
        rule_id = getattr(rule, "_edictum_id", None) or getattr(rule, "__name__", "unknown")
        try:
            decision = rule(tool_call)
        except Exception as exc:
            contract_result = RuleResult(
                rule_id=rule_id,
                contract_type="sandbox",
                passed=False,
                message=f"Sandbox error: {exc}",
                policy_error=True,
            )
            rules.append(contract_result)
            deny_reasons.append(contract_result.message)
            continue

        tags = decision.metadata.get("tags", []) if decision.metadata else []
        is_observed = getattr(rule, "_edictum_mode", None) == "observe" and not decision.passed
        pe = decision.metadata.get("policy_error", False) if decision.metadata else False

        contract_result = RuleResult(
            rule_id=rule_id,
            contract_type="sandbox",
            passed=decision.passed,
            message=decision.message,
            tags=tags,
            observed=is_observed,
            policy_error=pe,
        )
        rules.append(contract_result)

        if not decision.passed and not is_observed:
            deny_reasons.append(decision.message or "")

    # Evaluate postconditions only when output is provided
    if output is not None:
        for rule in self.get_postconditions(tool_call):
            rule_id = getattr(rule, "_edictum_id", None) or getattr(rule, "__name__", "unknown")
            try:
                decision = rule(tool_call, output)
            except Exception as exc:
                contract_result = RuleResult(
                    rule_id=rule_id,
                    contract_type="postcondition",
                    passed=False,
                    message=f"Postcondition error: {exc}",
                    policy_error=True,
                )
                rules.append(contract_result)
                warn_reasons.append(contract_result.message)
                continue

            tags = decision.metadata.get("tags", []) if decision.metadata else []
            is_observed = getattr(rule, "_edictum_mode", None) == "observe" and not decision.passed
            pe = decision.metadata.get("policy_error", False) if decision.metadata else False
            action = getattr(rule, "_edictum_effect", "warn")

            contract_result = RuleResult(
                rule_id=rule_id,
                contract_type="postcondition",
                passed=decision.passed,
                message=decision.message,
                tags=tags,
                observed=is_observed,
                action=action,
                policy_error=pe,
            )
            rules.append(contract_result)

            if not decision.passed and not is_observed:
                warn_reasons.append(decision.message or "")

    # Compute decision
    if deny_reasons:
        verdict_str = "block"
    elif warn_reasons:
        verdict_str = "warn"
    else:
        verdict_str = "allow"

    return EvaluationResult(
        decision=verdict_str,
        tool_name=tool_name,
        rules=rules,
        deny_reasons=deny_reasons,
        warn_reasons=warn_reasons,
        contracts_evaluated=len(rules),
        policy_error=any(r.policy_error for r in rules),
    )


def _evaluate_batch(self: Edictum, calls: list[dict[str, Any]]) -> list[EvaluationResult]:
    """Evaluate a batch of tool calls. Thin wrapper over evaluate()."""
    results: list[EvaluationResult] = []
    for call in calls:
        tool = call["tool"]
        args = call.get("args", {})

        # Convert principal dict to Principal object
        principal = None
        principal_data = call.get("principal")
        if principal_data and isinstance(principal_data, dict):
            principal = Principal(
                role=principal_data.get("role"),
                user_id=principal_data.get("user_id"),
                ticket_ref=principal_data.get("ticket_ref"),
                claims=principal_data.get("claims", {}),
            )

        # Normalize output
        output = call.get("output")
        if isinstance(output, dict):
            output = json.dumps(output)

        environment = call.get("environment")

        results.append(
            self.evaluate(
                tool,
                args,
                principal=principal,
                output=output,
                environment=environment,
            )
        )
    return results

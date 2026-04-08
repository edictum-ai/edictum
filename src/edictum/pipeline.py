"""CheckPipeline — single source of rule-evaluation logic."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from edictum.envelope import SideEffect, ToolCall
from edictum.hooks import HookDecision, HookResult
from edictum.rules import Decision
from edictum.session import Session

if TYPE_CHECKING:
    from edictum import Edictum

logger = logging.getLogger(__name__)


@dataclass
class PreDecision:
    """Result of pre-execution rule evaluation."""

    action: str  # "allow" | "block" | "pending_approval"
    reason: str | None = None
    decision_source: str | None = None
    decision_name: str | None = None
    hooks_evaluated: list[dict] = field(default_factory=list)
    contracts_evaluated: list[dict] = field(default_factory=list)
    observed: bool = False
    policy_error: bool = False
    observe_results: list[dict] = field(default_factory=list)
    approval_timeout: int = 300
    approval_timeout_action: str = "block"
    approval_message: str | None = None
    workflow: dict[str, Any] | None = None
    workflow_stage_id: str | None = None
    workflow_involved: bool = False
    workflow_events: list[dict] = field(default_factory=list)


@dataclass
class PostDecision:
    """Result of post-execution rule evaluation."""

    tool_success: bool
    postconditions_passed: bool
    warnings: list[str] = field(default_factory=list)
    contracts_evaluated: list[dict] = field(default_factory=list)
    policy_error: bool = False
    redacted_response: Any = None
    output_suppressed: bool = False


class CheckPipeline:
    """Orchestrates all rule checks.

    This is the single source of truth for rule-evaluation logic.
    Adapters call pre_execute() and post_execute(), then translate
    the structured results into framework-specific formats.
    """

    def __init__(self, guard: Edictum):
        self._guard = guard

    async def pre_execute(
        self,
        tool_call: ToolCall,
        session: Session,
    ) -> PreDecision:
        """Run all pre-execution rule checks."""
        hooks_evaluated: list[dict] = []
        contracts_evaluated: list[dict] = []
        has_observed_deny = False

        # Pre-fetch session counters in a single batch to reduce HTTP
        # round trips when using ServerBackend.  The tool-specific key
        # is included only when a per-tool limit is configured.
        tool_name_for_batch: str | None = None
        if tool_call.tool_name in self._guard.limits.max_calls_per_tool:
            tool_name_for_batch = tool_call.tool_name
        counters = await session.batch_get_counters(
            include_tool=tool_name_for_batch,
        )

        # 1. Attempt limit
        attempt_count = counters["attempts"]
        if attempt_count >= self._guard.limits.max_attempts:
            return PreDecision(
                action="block",
                reason=f"Attempt limit reached ({self._guard.limits.max_attempts}). "
                "Agent may be stuck in a retry loop. Stop and reassess.",
                decision_source="attempt_limit",
                decision_name="max_attempts",
                hooks_evaluated=hooks_evaluated,
                contracts_evaluated=contracts_evaluated,
            )

        # 2. Before hooks (Fix 5: catch exceptions)
        for hook_reg in self._guard.get_hooks("before", tool_call):
            if hook_reg.when and not hook_reg.when(tool_call):
                continue
            try:
                decision = hook_reg.callback(tool_call)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception("Hook %s raised", getattr(hook_reg.callback, "__name__", "anonymous"))
                decision = HookDecision.block(f"Hook error: {exc}")

            hook_record = {
                "name": getattr(hook_reg.callback, "__name__", "anonymous"),
                "result": decision.result.value,
                "reason": decision.reason,
            }
            hooks_evaluated.append(hook_record)

            if decision.result == HookResult.DENY:
                return PreDecision(
                    action="block",
                    reason=decision.reason,
                    decision_source="hook",
                    decision_name=hook_record["name"],
                    hooks_evaluated=hooks_evaluated,
                    contracts_evaluated=contracts_evaluated,
                    policy_error=True if "Hook error:" in (decision.reason or "") else False,
                )

        # 3. Preconditions (Fix 5: catch exceptions)
        for rule in self._guard.get_preconditions(tool_call):
            try:
                decision = rule(tool_call)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception("Precondition %s raised", getattr(rule, "__name__", "anonymous"))
                decision = Decision.fail(f"Precondition error: {exc}", policy_error=True)

            rule_mode = getattr(rule, "_edictum_mode", None)
            rule_record = {
                "name": getattr(rule, "__name__", "anonymous"),
                "type": "precondition",
                "passed": decision.passed,
                "message": decision.message,
            }
            if decision.metadata:
                rule_record["metadata"] = decision.metadata
            contracts_evaluated.append(rule_record)

            if not decision.passed:
                # Per-rule observe mode: record but don't block (Fix 4)
                if rule_mode == "observe":
                    rule_record["observed"] = True
                    has_observed_deny = True
                    continue

                source = getattr(rule, "_edictum_source", "precondition")
                pe = any(c.get("metadata", {}).get("policy_error") for c in contracts_evaluated)

                action = getattr(rule, "_edictum_effect", "block")
                if action == "ask":
                    return PreDecision(
                        action="pending_approval",
                        reason=decision.message,
                        decision_source=source,
                        decision_name=rule_record["name"],
                        hooks_evaluated=hooks_evaluated,
                        contracts_evaluated=contracts_evaluated,
                        policy_error=pe,
                        approval_timeout=getattr(rule, "_edictum_timeout", 300),
                        approval_timeout_action=getattr(rule, "_edictum_timeout_action", "block"),
                        approval_message=decision.message,
                    )

                return PreDecision(
                    action="block",
                    reason=decision.message,
                    decision_source=source,
                    decision_name=rule_record["name"],
                    hooks_evaluated=hooks_evaluated,
                    contracts_evaluated=contracts_evaluated,
                    policy_error=pe,
                )

        # 3.5. Sandbox rules
        for rule in self._guard.get_sandbox_contracts(tool_call):
            try:
                decision = rule(tool_call)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception("Sandbox rule %s raised", getattr(rule, "__name__", "anonymous"))
                decision = Decision.fail(f"Sandbox rule error: {exc}", policy_error=True)

            rule_mode = getattr(rule, "_edictum_mode", None)
            rule_record = {
                "name": getattr(rule, "__name__", "anonymous"),
                "type": "sandbox",
                "passed": decision.passed,
                "message": decision.message,
            }
            if decision.metadata:
                rule_record["metadata"] = decision.metadata
            contracts_evaluated.append(rule_record)

            if not decision.passed:
                if rule_mode == "observe":
                    rule_record["observed"] = True
                    has_observed_deny = True
                    continue

                source = getattr(rule, "_edictum_source", "yaml_sandbox")
                pe = any(c.get("metadata", {}).get("policy_error") for c in contracts_evaluated)

                action = getattr(rule, "_edictum_effect", "block")
                if action == "ask":
                    return PreDecision(
                        action="pending_approval",
                        reason=decision.message,
                        decision_source=source,
                        decision_name=rule_record["name"],
                        hooks_evaluated=hooks_evaluated,
                        contracts_evaluated=contracts_evaluated,
                        policy_error=pe,
                        approval_timeout=getattr(rule, "_edictum_timeout", 300),
                        approval_timeout_action=getattr(rule, "_edictum_timeout_action", "block"),
                        approval_message=decision.message,
                    )

                return PreDecision(
                    action="block",
                    reason=decision.message,
                    decision_source=source,
                    decision_name=rule_record["name"],
                    hooks_evaluated=hooks_evaluated,
                    contracts_evaluated=contracts_evaluated,
                    policy_error=pe,
                )

        # 4. Session rules (Fix 5: catch exceptions)
        for rule in self._guard.get_session_contracts():
            try:
                decision = rule(session)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception("Session rule %s raised", getattr(rule, "__name__", "anonymous"))
                decision = Decision.fail(f"Session rule error: {exc}", policy_error=True)

            rule_record = {
                "name": getattr(rule, "__name__", "anonymous"),
                "type": "session_contract",
                "passed": decision.passed,
                "message": decision.message,
            }
            if decision.metadata:
                rule_record["metadata"] = decision.metadata
            contracts_evaluated.append(rule_record)

            if not decision.passed:
                source = getattr(rule, "_edictum_source", "session_contract")
                pe = any(c.get("metadata", {}).get("policy_error") for c in contracts_evaluated)
                return PreDecision(
                    action="block",
                    reason=decision.message,
                    decision_source=source,
                    decision_name=rule_record["name"],
                    hooks_evaluated=hooks_evaluated,
                    contracts_evaluated=contracts_evaluated,
                    policy_error=pe,
                )

        workflow_meta: dict[str, Any] | None = None
        workflow_stage_id: str | None = None
        workflow_involved = False
        workflow_events: list[dict] = []

        # 5. Workflow gates
        if self._guard._workflow_runtime is not None:
            try:
                workflow_eval = await self._guard._workflow_runtime.evaluate(session, tool_call)
            except Exception as exc:
                rule_record = {
                    "name": "workflow:error",
                    "type": "workflow_gate",
                    "passed": False,
                    "message": f"Workflow evaluation error: {exc}",
                    "metadata": {"policy_error": True},
                }
                contracts_evaluated.append(rule_record)
                return PreDecision(
                    action="block",
                    reason=f"Workflow evaluation error: {exc}",
                    decision_source="workflow",
                    decision_name="workflow_error",
                    hooks_evaluated=hooks_evaluated,
                    contracts_evaluated=contracts_evaluated,
                    policy_error=True,
                    workflow=workflow_meta,
                    workflow_stage_id=workflow_stage_id,
                    workflow_involved=True,
                    workflow_events=workflow_events,
                )

            if workflow_eval.records:
                contracts_evaluated.extend(workflow_eval.records)
                workflow_stage_id = workflow_eval.stage_id or None
            if workflow_eval.audit is not None:
                workflow_meta = workflow_eval.audit
            if (
                workflow_eval.records
                or workflow_eval.events
                or workflow_eval.stage_id
                or workflow_eval.audit is not None
            ):
                workflow_involved = True
            workflow_events.extend(workflow_eval.events)

            if workflow_eval.action == "block":
                return PreDecision(
                    action="block",
                    reason=workflow_eval.reason,
                    decision_source="workflow",
                    decision_name=workflow_eval.stage_id or None,
                    hooks_evaluated=hooks_evaluated,
                    contracts_evaluated=contracts_evaluated,
                    policy_error=has_observed_deny
                    or any(c.get("metadata", {}).get("policy_error") for c in contracts_evaluated),
                    workflow=workflow_meta,
                    workflow_stage_id=workflow_stage_id,
                    workflow_involved=workflow_involved,
                    workflow_events=workflow_events,
                )
            if workflow_eval.action == "pending_approval":
                return PreDecision(
                    action="pending_approval",
                    reason=workflow_eval.reason,
                    decision_source="workflow",
                    decision_name=workflow_eval.stage_id or None,
                    hooks_evaluated=hooks_evaluated,
                    contracts_evaluated=contracts_evaluated,
                    policy_error=any(c.get("metadata", {}).get("policy_error") for c in contracts_evaluated),
                    approval_message=workflow_eval.reason or None,
                    workflow=workflow_meta,
                    workflow_stage_id=workflow_stage_id,
                    workflow_involved=workflow_involved,
                    workflow_events=workflow_events,
                )

        # 6. Execution limits (use pre-fetched counters)
        exec_count = counters["execs"]
        if exec_count >= self._guard.limits.max_tool_calls:
            return PreDecision(
                action="block",
                reason=f"Execution limit reached ({self._guard.limits.max_tool_calls} calls). "
                "Summarize progress and stop.",
                decision_source="operation_limit",
                decision_name="max_tool_calls",
                hooks_evaluated=hooks_evaluated,
                contracts_evaluated=contracts_evaluated,
                workflow=workflow_meta,
                workflow_stage_id=workflow_stage_id,
                workflow_involved=workflow_involved,
                workflow_events=workflow_events,
            )

        # Per-tool limits (use pre-fetched counter when available)
        if tool_call.tool_name in self._guard.limits.max_calls_per_tool:
            tool_key = f"tool:{tool_call.tool_name}"
            tool_count = counters.get(tool_key, 0)
            tool_limit = self._guard.limits.max_calls_per_tool[tool_call.tool_name]
            if tool_count >= tool_limit:
                return PreDecision(
                    action="block",
                    reason=f"Per-tool limit: {tool_call.tool_name} called {tool_count} times (limit: {tool_limit}).",
                    decision_source="operation_limit",
                    decision_name=f"max_calls_per_tool:{tool_call.tool_name}",
                    hooks_evaluated=hooks_evaluated,
                    contracts_evaluated=contracts_evaluated,
                    workflow=workflow_meta,
                    workflow_stage_id=workflow_stage_id,
                    workflow_involved=workflow_involved,
                    workflow_events=workflow_events,
                )

        # 6. All checks passed
        pe = any(c.get("metadata", {}).get("policy_error") for c in contracts_evaluated)

        # 7. Observe-mode rule evaluation (never affects the decision)
        observe_results = await self._evaluate_observe_rules(tool_call, session)

        return PreDecision(
            action="allow",
            hooks_evaluated=hooks_evaluated,
            contracts_evaluated=contracts_evaluated,
            observed=has_observed_deny,
            policy_error=pe,
            observe_results=observe_results,
            workflow=workflow_meta,
            workflow_stage_id=workflow_stage_id,
            workflow_involved=workflow_involved,
            workflow_events=workflow_events,
        )

    async def post_execute(
        self,
        tool_call: ToolCall,
        tool_response: Any,
        tool_success: bool,
    ) -> PostDecision:
        """Run all post-execution rule checks."""
        warnings: list[str] = []
        contracts_evaluated: list[dict] = []
        redacted_response: Any = None
        output_suppressed: bool = False

        # 1. Postconditions (Fix 5: catch exceptions)
        for rule in self._guard.get_postconditions(tool_call):
            try:
                decision = rule(tool_call, tool_response)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception("Postcondition %s raised", getattr(rule, "__name__", "anonymous"))
                decision = Decision.fail(f"Postcondition error: {exc}", policy_error=True)

            rule_mode = getattr(rule, "_edictum_mode", None)
            rule_record = {
                "name": getattr(rule, "__name__", "anonymous"),
                "type": "postcondition",
                "passed": decision.passed,
                "message": decision.message,
            }
            if rule_mode == "observe":
                rule_record["observed"] = True
            if decision.metadata:
                rule_record["metadata"] = decision.metadata
            contracts_evaluated.append(rule_record)

            if not decision.passed:
                action = getattr(rule, "_edictum_effect", "warn")
                is_safe = tool_call.side_effect in (SideEffect.PURE, SideEffect.READ)

                # Observe mode takes precedence
                if rule_mode == "observe":
                    warnings.append(f"\u26a0\ufe0f [observe] {decision.message}")
                elif action == "redact" and is_safe:
                    patterns = getattr(rule, "_edictum_redact_patterns", [])
                    source = redacted_response if redacted_response is not None else tool_response
                    text = str(source) if source is not None else ""
                    if patterns:
                        for pat in patterns:
                            text = pat.sub("[REDACTED]", text)
                    else:
                        from edictum.audit import RedactionPolicy

                        text = RedactionPolicy().redact_result(text, max_length=len(text) + 100)
                    redacted_response = text
                    warnings.append(f"\u26a0\ufe0f Content redacted by {rule_record['name']}.")
                elif action == "block" and is_safe:
                    redacted_response = f"[OUTPUT SUPPRESSED] {decision.message}"
                    output_suppressed = True
                    warnings.append(f"\u26a0\ufe0f Output suppressed by {rule_record['name']}.")
                elif action in ("redact", "block") and not is_safe:
                    logger.warning(
                        "Postcondition %s declares action=%s but tool %s has side_effect=%s; falling back to warn.",
                        rule_record["name"],
                        action,
                        tool_call.tool_name,
                        tool_call.side_effect.value,
                    )
                    warnings.append(
                        f"\u26a0\ufe0f {decision.message} Tool already executed \u2014 assess before proceeding."
                    )
                elif is_safe:
                    warnings.append(f"\u26a0\ufe0f {decision.message} Consider retrying.")
                else:
                    warnings.append(
                        f"\u26a0\ufe0f {decision.message} Tool already executed \u2014 assess before proceeding."
                    )

        # 2. Observe-mode postconditions (from observe_alongside bundles)
        for rule in self._guard.get_observe_postconditions(tool_call):
            try:
                decision = rule(tool_call, tool_response)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception(
                    "Observe-mode postcondition %s raised",
                    getattr(rule, "__name__", "anonymous"),
                )
                decision = Decision.fail(f"Observe-mode postcondition error: {exc}", policy_error=True)

            rule_record = {
                "name": getattr(rule, "__name__", "anonymous"),
                "type": "postcondition",
                "passed": decision.passed,
                "message": decision.message,
                "observed": True,
            }
            if decision.metadata:
                rule_record["metadata"] = decision.metadata
            contracts_evaluated.append(rule_record)

            if not decision.passed:
                warnings.append(f"\u26a0\ufe0f [observe] {decision.message}")

        # 3. After hooks (Fix 5: catch exceptions)
        for hook_reg in self._guard.get_hooks("after", tool_call):
            if hook_reg.when and not hook_reg.when(tool_call):
                continue
            try:
                result = hook_reg.callback(tool_call, tool_response)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("After hook %s raised", getattr(hook_reg.callback, "__name__", "anonymous"))

        # Exclude observe-mode rules — they must never affect postconditions_passed,
        # which propagates to on_postcondition_warn callbacks in all adapters.
        enforce_rules = [c for c in contracts_evaluated if not c.get("observed")]
        postconditions_passed = all(c["passed"] for c in enforce_rules) if enforce_rules else True
        pe = any(c.get("metadata", {}).get("policy_error") for c in contracts_evaluated)

        return PostDecision(
            tool_success=tool_success,
            postconditions_passed=postconditions_passed,
            warnings=warnings,
            contracts_evaluated=contracts_evaluated,
            policy_error=pe,
            redacted_response=redacted_response,
            output_suppressed=output_suppressed,
        )

    async def _evaluate_observe_rules(
        self,
        tool_call: ToolCall,
        session: Session,
    ) -> list[dict]:
        """Evaluate observe-mode rules without affecting the real decision.

        Observe-mode rules are identified by ``_edictum_observe = True``.
        Results are returned as dicts for audit emission but never block calls.
        """
        results: list[dict] = []

        # Observe-mode preconditions
        for rule in self._guard.get_observe_preconditions(tool_call):
            try:
                decision = rule(tool_call)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception("Observe-mode precondition %s raised", getattr(rule, "__name__", "anonymous"))
                decision = Decision.fail(f"Observe-mode precondition error: {exc}", policy_error=True)

            results.append(
                {
                    "name": getattr(rule, "__name__", "anonymous"),
                    "type": "precondition",
                    "passed": decision.passed,
                    "message": decision.message,
                    "source": getattr(rule, "_edictum_source", "yaml_precondition"),
                }
            )

        # Observe-mode sandbox rules
        for rule in self._guard.get_observe_sandbox_contracts(tool_call):
            try:
                decision = rule(tool_call)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception("Observe-mode sandbox %s raised", getattr(rule, "__name__", "anonymous"))
                decision = Decision.fail(f"Observe-mode sandbox error: {exc}", policy_error=True)

            results.append(
                {
                    "name": getattr(rule, "__name__", "anonymous"),
                    "type": "sandbox",
                    "passed": decision.passed,
                    "message": decision.message,
                    "source": getattr(rule, "_edictum_source", "yaml_sandbox"),
                }
            )

        # Observe-mode session rules — evaluate against the real session
        for rule in self._guard.get_observe_session_contracts():
            try:
                decision = rule(session)
                if asyncio.iscoroutine(decision):
                    decision = await decision
            except Exception as exc:
                logger.exception("Observe-mode session rule %s raised", getattr(rule, "__name__", "anonymous"))
                decision = Decision.fail(f"Observe-mode session rule error: {exc}", policy_error=True)

            results.append(
                {
                    "name": getattr(rule, "__name__", "anonymous"),
                    "type": "session_contract",
                    "passed": decision.passed,
                    "message": decision.message,
                    "source": getattr(rule, "_edictum_source", "yaml_session"),
                }
            )

        return results

"""Claude Agent SDK adapter — thin translation layer."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from edictum.audit import AuditAction, AuditEvent
from edictum.envelope import Principal, create_envelope
from edictum.findings import Finding, build_findings
from edictum.pipeline import CheckPipeline
from edictum.session import Session

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from edictum import Edictum


class ClaudeAgentSDKAdapter:
    """Translate Edictum pipeline decisions into Claude SDK hook format.

    The adapter does NOT contain governance logic -- that lives in
    CheckPipeline. The adapter only:
    1. Creates envelopes from SDK input
    2. Manages pending state (tool_call + span) between Pre/Post
    3. Translates PreDecision/PostDecision into SDK hook output format
    4. Handles observe mode (block -> allow conversion)

    Note: Hook callables (to_hook_callables) cannot substitute tool results.
    Postcondition effects (redact/block) require the wrapper integration path
    for full enforcement. Native hooks can only warn.
    """

    def __init__(
        self,
        guard: Edictum,
        session_id: str | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    ):
        self._guard = guard
        self._pipeline = CheckPipeline(guard)
        self._session_id = session_id or str(uuid.uuid4())
        self._session = Session(self._session_id, guard.backend)
        self._call_index = 0
        self._pending: dict[str, tuple[Any, Any]] = {}
        self._principal = principal
        self._principal_resolver = principal_resolver

    @property
    def session_id(self) -> str:
        return self._session_id

    def set_principal(self, principal: Principal) -> None:
        """Update the principal for subsequent tool calls."""
        self._principal = principal

    def _resolve_principal(self, tool_name: str, tool_input: dict[str, Any]) -> Principal | None:
        """Resolve principal: resolver overrides static."""
        if self._principal_resolver is not None:
            return self._principal_resolver(tool_name, tool_input)
        return self._principal

    def to_hook_callables(
        self,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> dict:
        """Return raw hook callables for manual agent-loop integration.

        Returns a dict with ``pre_tool_use`` and ``post_tool_use`` async
        functions that use Edictum's own calling convention::

            hooks = adapter.to_hook_callables()
            result = await hooks["pre_tool_use"](tool_name, tool_input, tool_use_id)
            result = await hooks["post_tool_use"](tool_use_id=id, tool_response=resp)

        These are **not** directly compatible with
        ``ClaudeAgentOptions(hooks=...)``.  See the adapter docs for a bridge
        recipe that wraps them into SDK-native format.

        Args:
            on_postcondition_warn: Optional callback invoked when postconditions
                detect issues. Receives (original_result, violations) and is called
                for side effects.
        """
        self._on_postcondition_warn = on_postcondition_warn

        has_effects = any(getattr(p, "_edictum_effect", "warn") != "warn" for p in self._guard._state.postconditions)
        if has_effects:
            logger.warning(
                "Postcondition effects (redact/block) require the wrapper integration path "
                "for full enforcement. Hook callables can only warn."
            )

        return {
            "pre_tool_use": self._pre_tool_use,
            "post_tool_use": self._post_tool_use,
        }

    async def _pre_tool_use(self, tool_name: str, tool_input: dict, tool_use_id: str, **kwargs) -> dict:
        # Create tool_call
        tool_call = create_envelope(
            tool_name=tool_name,
            tool_input=tool_input,
            run_id=self._session_id,
            call_index=self._call_index,
            tool_use_id=tool_use_id,
            environment=self._guard.environment,
            registry=self._guard.tool_registry,
            principal=self._resolve_principal(tool_name, tool_input),
        )
        self._call_index += 1

        # Increment attempts BEFORE governance
        await self._session.increment_attempts()

        # Start OTel span
        span = self._guard.telemetry.start_tool_span(tool_call)

        try:
            # Run pipeline
            decision = await self._pipeline.pre_execute(tool_call, self._session)

            # Handle observe mode: convert block to allow with warning
            if self._guard.mode == "observe" and decision.action == "block":
                await self._emit_audit_pre(tool_call, decision, audit_action=AuditAction.CALL_WOULD_DENY)
                span.set_attribute("governance.action", "would_deny")
                span.set_attribute("governance.would_deny_reason", decision.reason)
                self._pending[tool_use_id] = (tool_call, span)
                return {}  # allow through

            # Handle block
            if decision.action == "block":
                await self._emit_audit_pre(tool_call, decision)
                self._guard.telemetry.record_denial(tool_call, decision.reason)
                if self._guard._on_deny:
                    try:
                        self._guard._on_deny(tool_call, decision.reason or "", decision.decision_name)
                    except Exception:
                        logger.exception("on_deny callback raised")
                span.set_attribute("governance.action", "denied")
                self._guard.telemetry.set_span_error(span, decision.reason or "denied")
                span.end()
                self._pending.pop(tool_use_id, None)
                return self._deny(decision.reason)

            # Handle per-rule observed denials
            if decision.observed:
                for cr in decision.contracts_evaluated:
                    if cr.get("observed") and not cr.get("passed"):
                        await self._guard.audit_sink.emit(
                            AuditEvent(
                                action=AuditAction.CALL_WOULD_DENY,
                                run_id=tool_call.run_id,
                                call_id=tool_call.call_id,
                                call_index=tool_call.call_index,
                                tool_name=tool_call.tool_name,
                                tool_args=self._guard.redaction.redact_args(tool_call.args),
                                side_effect=tool_call.side_effect.value,
                                environment=tool_call.environment,
                                principal=asdict(tool_call.principal) if tool_call.principal else None,
                                decision_source="precondition",
                                decision_name=cr["name"],
                                reason=cr["message"],
                                mode="observe",
                                policy_version=self._guard.policy_version,
                                policy_error=decision.policy_error,
                            )
                        )

            # Handle allow
            await self._emit_audit_pre(tool_call, decision)
            if self._guard._on_allow:
                try:
                    self._guard._on_allow(tool_call)
                except Exception:
                    logger.exception("on_allow callback raised")
            span.set_attribute("governance.action", "allowed")
            self._pending[tool_use_id] = (tool_call, span)
            return {}

        except Exception:
            if tool_use_id not in self._pending:
                span.end()
            raise

    async def _post_tool_use(self, tool_use_id: str, tool_response: Any = None, **kwargs) -> dict:
        pending = self._pending.pop(tool_use_id, None)
        if not pending:
            return {}

        tool_call, span = pending

        try:
            # Derive tool_success from SDK response
            tool_success = self._check_tool_success(tool_call.tool_name, tool_response)

            # Run pipeline
            post_decision = await self._pipeline.post_execute(tool_call, tool_response, tool_success)

            # Record in session
            await self._session.record_execution(tool_call.tool_name, success=tool_success)

            # Emit audit
            action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
            await self._guard.audit_sink.emit(
                AuditEvent(
                    action=action,
                    run_id=tool_call.run_id,
                    call_id=tool_call.call_id,
                    call_index=tool_call.call_index,
                    tool_name=tool_call.tool_name,
                    tool_args=self._guard.redaction.redact_args(tool_call.args),
                    side_effect=tool_call.side_effect.value,
                    environment=tool_call.environment,
                    principal=asdict(tool_call.principal) if tool_call.principal else None,
                    tool_success=tool_success,
                    postconditions_passed=post_decision.postconditions_passed,
                    contracts_evaluated=post_decision.contracts_evaluated,
                    session_attempt_count=await self._session.attempt_count(),
                    session_execution_count=await self._session.execution_count(),
                    mode=self._guard.mode,
                    policy_version=self._guard.policy_version,
                    policy_error=post_decision.policy_error,
                )
            )

            span.set_attribute("governance.tool_success", tool_success)
            span.set_attribute("governance.postconditions_passed", post_decision.postconditions_passed)

            if tool_success:
                self._guard.telemetry.set_span_ok(span)
            else:
                self._guard.telemetry.set_span_error(span, "tool execution failed")
        finally:
            span.end()

        # Build violations and call callback with effective response
        effective_response = (
            post_decision.redacted_response if post_decision.redacted_response is not None else tool_response
        )
        violations = build_findings(post_decision)
        on_warn = getattr(self, "_on_postcondition_warn", None)
        if not post_decision.postconditions_passed and violations and on_warn:
            try:
                on_warn(effective_response, violations)
            except Exception:
                logger.exception("on_postcondition_warn callback raised")

        # Return warnings as additionalContext
        if post_decision.warnings:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": "\n".join(post_decision.warnings),
                }
            }
        return {}

    async def _emit_audit_pre(self, tool_call, decision, audit_action=None):
        if audit_action is None:
            audit_action = AuditAction.CALL_DENIED if decision.action == "block" else AuditAction.CALL_ALLOWED

        await self._guard.audit_sink.emit(
            AuditEvent(
                action=audit_action,
                run_id=tool_call.run_id,
                call_id=tool_call.call_id,
                call_index=tool_call.call_index,
                tool_name=tool_call.tool_name,
                tool_args=self._guard.redaction.redact_args(tool_call.args),
                side_effect=tool_call.side_effect.value,
                environment=tool_call.environment,
                principal=asdict(tool_call.principal) if tool_call.principal else None,
                decision_source=decision.decision_source,
                decision_name=decision.decision_name,
                reason=decision.reason,
                hooks_evaluated=decision.hooks_evaluated,
                contracts_evaluated=decision.contracts_evaluated,
                session_attempt_count=await self._session.attempt_count(),
                session_execution_count=await self._session.execution_count(),
                mode=self._guard.mode,
                policy_version=self._guard.policy_version,
                policy_error=decision.policy_error,
            )
        )

    def _check_tool_success(self, tool_name: str, tool_response: Any) -> bool:
        if self._guard._success_check is not None:
            return self._guard._success_check(tool_name, tool_response)
        if tool_response is None:
            return True
        if isinstance(tool_response, dict):
            if tool_response.get("is_error"):
                return False
        if isinstance(tool_response, str):
            lower = tool_response[:7].lower()
            if lower.startswith("error:") or lower.startswith("fatal:"):
                return False
        return True

    def _deny(self, reason):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "block",
                "permissionDecisionReason": reason,
            }
        }

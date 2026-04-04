"""Semantic Kernel adapter — kernel filter for tool call governance."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict, replace
from typing import TYPE_CHECKING, Any

from edictum.approval import ApprovalStatus
from edictum.audit import AuditAction, AuditEvent
from edictum.envelope import Principal, create_envelope
from edictum.findings import Finding, PostCallResult, build_findings
from edictum.pipeline import CheckPipeline
from edictum.session import Session, validate_session_id

logger = logging.getLogger(__name__)
_MAX_WORKFLOW_APPROVAL_ROUNDS = 32

if TYPE_CHECKING:
    from edictum import Edictum


class SemanticKernelAdapter:
    """Translate Edictum pipeline decisions into Semantic Kernel filter format.

    The adapter does NOT contain governance logic -- that lives in
    CheckPipeline. The adapter only:
    1. Creates envelopes from SK AutoFunctionInvocationContext
    2. Manages pending state (envelope + span) between pre/post
    3. Translates PreDecision/PostDecision into SK filter output
    4. Handles observe mode (block -> allow conversion)
    """

    def __init__(
        self,
        guard: Edictum,
        session_id: str | None = None,
        principal: Principal | None = None,
        terminate_on_block: bool = True,
        terminate_on_deny: bool | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    ):
        self._guard = guard
        self._pipeline = CheckPipeline(guard)
        self._session_id = session_id or str(uuid.uuid4())
        self._session = Session(self._session_id, guard.backend)
        self._call_index = 0
        self._pending: dict[str, tuple[Any, Any]] = {}
        self._pending_decisions: dict[str, Any] = {}
        self._principal = principal
        if terminate_on_deny is not None:
            terminate_on_block = terminate_on_deny
        self._terminate_on_deny = terminate_on_block
        self._principal_resolver = principal_resolver
        self._parent_session_id: str | None = None

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

    def _audit_parent_session_id(self) -> str | None:
        value = self._parent_session_id
        if not isinstance(value, str) or not value:
            return None
        try:
            validate_session_id(value)
        except ValueError:
            return None
        return value

    def register(
        self,
        kernel: Any,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> None:
        """Register AUTO_FUNCTION_INVOCATION filter on the kernel.

        Args:
            kernel: Semantic Kernel instance.
            on_postcondition_warn: Optional callback invoked when postconditions
                detect issues. Receives (original_result, violations) and returns
                the (possibly transformed) result. The return value replaces
                context.function_result.

        Usage::

            from semantic_kernel.kernel import Kernel

            kernel = Kernel()
            guard = Edictum(...)
            adapter = SemanticKernelAdapter(guard)
            adapter.register(kernel)
        """
        self._on_postcondition_warn = on_postcondition_warn

        from semantic_kernel.filters import FilterTypes
        from semantic_kernel.functions import FunctionResult

        adapter = self

        def _wrap_result(context, value):
            """Wrap a value in a FunctionResult for the current context."""
            return FunctionResult(function=context.function.metadata, value=value)

        @kernel.filter(FilterTypes.AUTO_FUNCTION_INVOCATION)
        async def edictum_filter(context, next):  # noqa: N807
            call_id = str(uuid.uuid4())
            tool_name = context.function.name
            tool_input = dict(context.arguments) if context.arguments else {}

            pre_result = await adapter._pre(tool_name, tool_input, call_id)

            if isinstance(pre_result, str):
                # Blocked: set the result and stop the pipeline.
                context.function_result = _wrap_result(context, pre_result)
                if adapter._terminate_on_deny:
                    context.terminate = True
                return

            # Allowed — call next to execute
            await next(context)

            # Post-execute with function result
            tool_response = context.function_result
            post_result = await adapter._post(call_id, tool_response)

            # Apply remediation callback
            if not post_result.postconditions_passed and adapter._on_postcondition_warn:
                try:
                    remediated = adapter._on_postcondition_warn(post_result.result, post_result.violations)
                    context.function_result = _wrap_result(context, remediated)
                except Exception:
                    logger.exception("on_postcondition_warn callback raised")

    async def _pre(self, tool_name: str, tool_input: dict, call_id: str) -> dict | str:
        """Pre-execution governance. Returns {} to allow or denial string to deny."""
        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=tool_input,
            run_id=self._session_id,
            call_index=self._call_index,
            tool_use_id=call_id,
            environment=self._guard.environment,
            registry=self._guard.tool_registry,
            principal=self._resolve_principal(tool_name, tool_input),
        )
        self._call_index += 1

        await self._session.increment_attempts()

        span = self._guard.telemetry.start_tool_span(envelope)

        try:
            decision = await self._pipeline.pre_execute(envelope, self._session)
            await self._emit_workflow_events(envelope, decision.workflow_events)

            # Observe mode: convert block to allow with WOULD_DENY audit
            if self._guard.mode == "observe" and decision.action == "block":
                await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_WOULD_DENY)
                span.set_attribute("governance.action", "would_deny")
                span.set_attribute("governance.would_deny_reason", decision.reason)
                self._pending[call_id] = (envelope, span)
                self._pending_decisions[call_id] = decision
                return {}  # allow through

            # Block
            if decision.action == "block":
                await self._emit_audit_pre(envelope, decision)
                self._guard.telemetry.record_denial(envelope, decision.reason)
                if self._guard._on_deny:
                    try:
                        self._guard._on_deny(envelope, decision.reason or "", decision.decision_name)
                    except Exception:
                        logger.exception("on_deny callback raised")
                span.set_attribute("governance.action", "denied")
                self._guard.telemetry.set_span_error(span, decision.reason or "denied")
                span.end()
                self._pending.pop(call_id, None)
                self._pending_decisions.pop(call_id, None)
                return self._deny(decision.reason or "")

            if decision.action == "pending_approval":
                blocked_result, decision = await self._resolve_pending_approval(envelope, decision, span)
                if blocked_result is not None:
                    self._pending.pop(call_id, None)
                    self._pending_decisions.pop(call_id, None)
                    return blocked_result

            # Handle per-rule observed blocks
            if decision.observed:
                for cr in decision.contracts_evaluated:
                    if cr.get("observed") and not cr.get("passed"):
                        await self._guard.audit_sink.emit(
                            AuditEvent(
                                action=AuditAction.CALL_WOULD_DENY,
                                run_id=envelope.run_id,
                                call_id=envelope.call_id,
                                call_index=envelope.call_index,
                                session_id=self._session_id,
                                parent_session_id=self._audit_parent_session_id(),
                                tool_name=envelope.tool_name,
                                tool_args=self._guard.redaction.redact_args(envelope.args),
                                side_effect=envelope.side_effect.value,
                                environment=envelope.environment,
                                principal=asdict(envelope.principal) if envelope.principal else None,
                                decision_source="precondition",
                                decision_name=cr["name"],
                                reason=cr["message"],
                                mode="observe",
                                policy_version=self._guard.policy_version,
                                policy_error=decision.policy_error,
                            )
                        )

            # Allow
            await self._emit_audit_pre(envelope, decision)
            if self._guard._on_allow:
                try:
                    self._guard._on_allow(envelope)
                except Exception:
                    logger.exception("on_allow callback raised")
            span.set_attribute("governance.action", "allowed")
            self._pending[call_id] = (envelope, span)
            self._pending_decisions[call_id] = decision
            return {}

        except Exception:
            if call_id not in self._pending:
                span.end()
            raise

    async def _post(self, call_id: str, tool_response: Any = None) -> PostCallResult:
        """Post-execution governance. Returns PostCallResult with violations."""
        pending = self._pending.pop(call_id, None)
        if not pending:
            return PostCallResult(result=tool_response)

        decision = self._pending_decisions.pop(call_id, None)
        if decision is None:
            _, span = pending
            span.end()
            return PostCallResult(result=tool_response)

        envelope, span = pending

        try:
            tool_success = self._check_tool_success(envelope.tool_name, tool_response)

            post_decision = await self._pipeline.post_execute(envelope, tool_response, tool_success)

            effective_response = (
                post_decision.redacted_response if post_decision.redacted_response is not None else tool_response
            )

            workflow_events: list[dict] = []
            if (
                tool_success
                and decision.workflow_involved
                and decision.workflow_stage_id
                and self._guard._workflow_runtime
            ):
                workflow_events = await self._guard._workflow_runtime.record_result(
                    self._session,
                    decision.workflow_stage_id,
                    envelope,
                )

            await self._session.record_execution(envelope.tool_name, success=tool_success)

            action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
            await self._guard.audit_sink.emit(
                AuditEvent(
                    action=action,
                    run_id=envelope.run_id,
                    call_id=envelope.call_id,
                    call_index=envelope.call_index,
                    session_id=self._session_id,
                    parent_session_id=self._audit_parent_session_id(),
                    tool_name=envelope.tool_name,
                    tool_args=self._guard.redaction.redact_args(envelope.args),
                    side_effect=envelope.side_effect.value,
                    environment=envelope.environment,
                    principal=asdict(envelope.principal) if envelope.principal else None,
                    tool_success=tool_success,
                    postconditions_passed=post_decision.postconditions_passed,
                    contracts_evaluated=post_decision.contracts_evaluated,
                    session_attempt_count=await self._session.attempt_count(),
                    session_execution_count=await self._session.execution_count(),
                    mode=self._guard.mode,
                    policy_version=self._guard.policy_version,
                    policy_error=post_decision.policy_error,
                    workflow=decision.workflow,
                )
            )
            await self._emit_workflow_events(envelope, workflow_events)

            span.set_attribute("governance.tool_success", tool_success)
            span.set_attribute("governance.postconditions_passed", post_decision.postconditions_passed)

            if tool_success:
                self._guard.telemetry.set_span_ok(span)
            else:
                self._guard.telemetry.set_span_error(span, "tool execution failed")
        finally:
            span.end()

        findings = build_findings(post_decision)
        return PostCallResult(
            result=effective_response,
            postconditions_passed=post_decision.postconditions_passed,
            violations=findings,
        )

    async def _emit_audit_pre(self, envelope: Any, decision: Any, audit_action: AuditAction | None = None) -> None:
        if audit_action is None:
            audit_action = AuditAction.CALL_DENIED if decision.action == "block" else AuditAction.CALL_ALLOWED

        await self._guard.audit_sink.emit(
            AuditEvent(
                action=audit_action,
                run_id=envelope.run_id,
                call_id=envelope.call_id,
                call_index=envelope.call_index,
                session_id=self._session_id,
                parent_session_id=self._audit_parent_session_id(),
                tool_name=envelope.tool_name,
                tool_args=self._guard.redaction.redact_args(envelope.args),
                side_effect=envelope.side_effect.value,
                environment=envelope.environment,
                principal=asdict(envelope.principal) if envelope.principal else None,
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
                workflow=decision.workflow,
            )
        )

    async def _emit_workflow_events(self, envelope: Any, events: list[dict]) -> None:
        for record in events:
            workflow = record.get("workflow")
            action_name = record.get("action")
            if not isinstance(workflow, dict) or not isinstance(action_name, str):
                continue
            action = AuditAction.WORKFLOW_STAGE_ADVANCED
            if action_name == AuditAction.WORKFLOW_COMPLETED.value:
                action = AuditAction.WORKFLOW_COMPLETED
            await self._guard.audit_sink.emit(
                AuditEvent(
                    action=action,
                    run_id=envelope.run_id,
                    call_id=envelope.call_id,
                    call_index=envelope.call_index,
                    session_id=self._session_id,
                    parent_session_id=self._audit_parent_session_id(),
                    tool_name=envelope.tool_name,
                    tool_args=self._guard.redaction.redact_args(envelope.args),
                    side_effect=envelope.side_effect.value,
                    environment=envelope.environment,
                    principal=asdict(envelope.principal) if envelope.principal else None,
                    mode=self._guard.mode,
                    policy_version=self._guard.policy_version,
                    workflow=dict(workflow),
                )
            )

    async def _resolve_pending_approval(
        self,
        envelope: Any,
        decision: Any,
        span: Any,
    ) -> tuple[str | None, Any]:
        current = decision
        for _ in range(_MAX_WORKFLOW_APPROVAL_ROUNDS):
            blocked_result = await self._handle_approval(envelope, current, span)
            if blocked_result is not None:
                return blocked_result, current
            if (
                current.decision_source != "workflow"
                or not current.workflow_stage_id
                or self._guard._workflow_runtime is None
            ):
                return None, replace(current, action="allow")
            await self._guard._workflow_runtime.record_approval(self._session, current.workflow_stage_id)
            current = await self._pipeline.pre_execute(envelope, self._session)
            await self._emit_workflow_events(envelope, current.workflow_events)
            if current.action != "pending_approval":
                return None, current
        raise RuntimeError(f"workflow: exceeded maximum approval rounds ({_MAX_WORKFLOW_APPROVAL_ROUNDS})")

    async def _handle_approval(self, envelope: Any, decision: Any, span: Any) -> str | None:
        if self._guard._approval_backend is None:
            reason = "Approval required but no approval backend configured"
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_DENIED)
            self._guard.telemetry.record_denial(envelope, reason)
            if self._guard._on_deny:
                try:
                    self._guard._on_deny(envelope, reason, decision.decision_name)
                except Exception:
                    logger.exception("on_deny callback raised")
            span.set_attribute("governance.action", "denied")
            self._guard.telemetry.set_span_error(span, reason)
            span.end()
            return self._deny(reason)

        principal_dict = asdict(envelope.principal) if envelope.principal else None
        approval_request = await self._guard._approval_backend.request_approval(
            tool_name=envelope.tool_name,
            tool_args=envelope.args,
            message=decision.approval_message or decision.reason or "",
            timeout=decision.approval_timeout,
            timeout_action=decision.approval_timeout_action,
            principal=principal_dict,
        )
        await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_APPROVAL_REQUESTED)

        approval_decision = await self._guard._approval_backend.wait_for_decision(
            approval_id=approval_request.approval_id,
            timeout=decision.approval_timeout,
        )

        approved = approval_decision.approved
        if approval_decision.status == ApprovalStatus.TIMEOUT:
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_APPROVAL_TIMEOUT)
            if decision.approval_timeout_action == "allow":
                approved = True
        elif approval_decision.approved:
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_APPROVAL_GRANTED)
        else:
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_APPROVAL_DENIED)

        if approved:
            span_action = "approved"
            if approval_decision.status == ApprovalStatus.TIMEOUT and decision.approval_timeout_action == "allow":
                span_action = "timeout_allow"
            span.set_attribute("governance.action", span_action)
            return None

        reason = approval_decision.reason or decision.reason or "Approval blocked"
        if not approved and approval_decision.status == ApprovalStatus.TIMEOUT:
            reason = f"Approval timed out: {reason}"
        self._guard.telemetry.record_denial(envelope, reason)
        if self._guard._on_deny:
            try:
                self._guard._on_deny(envelope, reason, decision.decision_name)
            except Exception:
                logger.exception("on_deny callback raised")
        span.set_attribute("governance.action", "denied")
        self._guard.telemetry.set_span_error(span, reason)
        span.end()
        return self._deny(f"Approval blocked: {reason}")

    def _check_tool_success(self, tool_name: str, tool_response: Any) -> bool:
        if self._guard._success_check is not None:
            return bool(self._guard._success_check(tool_name, tool_response))
        if tool_response is None:
            return True
        if isinstance(tool_response, dict):
            if tool_response.get("is_error"):
                return False
        if isinstance(tool_response, str):
            lower = tool_response[:7].lower()
            if lower.startswith("error:") or lower.startswith("fatal:"):
                return False
        # Check for SK FunctionResult with error metadata
        error_meta = getattr(tool_response, "metadata", None)
        if isinstance(error_meta, dict) and error_meta.get("error"):
            return False
        return True

    def _deny(self, reason: str) -> str:
        """Return a denial string to set as function_result."""
        return f"DENIED: {reason}"

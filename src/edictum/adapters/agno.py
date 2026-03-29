"""Agno adapter — wrap-around tool_hook translation layer."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict, replace
from typing import TYPE_CHECKING, Any

from edictum.approval import ApprovalStatus
from edictum.audit import AuditAction, AuditEvent
from edictum.envelope import Principal, create_envelope
from edictum.findings import Finding, PostCallResult, build_findings
from edictum.pipeline import GovernancePipeline
from edictum.session import Session

logger = logging.getLogger(__name__)
_MAX_WORKFLOW_APPROVAL_ROUNDS = 32

if TYPE_CHECKING:
    from edictum import Edictum


class AgnoAdapter:
    """Translate Edictum pipeline decisions into Agno tool_hook format.

    The adapter does NOT contain governance logic -- that lives in
    GovernancePipeline. The adapter only:
    1. Creates envelopes from Agno hook input
    2. Manages pending state (envelope + span) between pre/post
    3. Translates PreDecision/PostDecision into Agno hook output format
    4. Handles observe mode (deny -> allow conversion)

    Agno tool_hooks use a wrap-around pattern: a single function receives
    (function_name, function_call, arguments) and must call function_call
    itself or return a denial string.
    """

    def __init__(
        self,
        guard: Edictum,
        session_id: str | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    ):
        self._guard = guard
        self._pipeline = GovernancePipeline(guard)
        self._session_id = session_id or str(uuid.uuid4())
        self._session = Session(self._session_id, guard.backend)
        self._call_index = 0
        self._pending: dict[str, tuple[Any, Any]] = {}
        self._pending_decisions: dict[str, Any] = {}
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

    def as_tool_hook(
        self,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> Callable:
        """Return a wrap-around hook function for Agno's tool_hooks parameter.

        Args:
            on_postcondition_warn: Optional callback invoked when postconditions
                detect issues. Receives (original_result, findings) and returns
                the (possibly transformed) result.

        Returns a function matching:
            (function_name: str, function_call: Callable, arguments: dict) -> result
        """
        self._on_postcondition_warn = on_postcondition_warn

        def hook(function_name: str, function_call: Callable, arguments: dict[str, Any]) -> Any:
            loop: asyncio.AbstractEventLoop | None = None
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                pass

            if loop and loop.is_running():
                # Bridge async→sync: Agno tool_hooks are sync but our pipeline
                # is async. We run in a fresh thread+event-loop to avoid
                # "cannot call asyncio.run() while another loop is running".
                # Caveat: objects with thread-affinity (e.g. some DB connections)
                # won't transfer. If Agno adds native async hook support, prefer that.
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(
                        asyncio.run,
                        self._hook_async(function_name, function_call, arguments),
                    ).result()
            return asyncio.run(self._hook_async(function_name, function_call, arguments))

        return hook

    async def _hook_async(self, function_name: str, function_call: Callable, arguments: dict[str, Any]) -> Any:
        """Full wrap-around lifecycle: pre -> execute -> post."""
        call_id = str(uuid.uuid4())

        # Pre-execute
        pre_result = await self._pre(function_name, arguments, call_id)

        # If denied, return denial string
        if isinstance(pre_result, str) and pre_result.startswith("DENIED:"):
            return pre_result

        # Execute the tool
        try:
            result = function_call(**arguments)
            if asyncio.iscoroutine(result):
                result = await result
            if self._guard._success_check is not None:
                tool_success = self._guard._success_check(function_name, result)
            else:
                tool_success = True
        except Exception as exc:
            result = f"Error: {exc}"
            tool_success = False

        # Post-execute
        post_result = await self._post(call_id, result, tool_success=tool_success)

        # Apply remediation callback if postconditions warned
        on_warn = getattr(self, "_on_postcondition_warn", None)
        if not post_result.postconditions_passed and on_warn:
            try:
                return on_warn(post_result.result, post_result.findings)
            except Exception:
                logger.exception("on_postcondition_warn callback raised")

        return post_result.result

    async def _pre(self, tool_name: str, tool_input: dict, call_id: str) -> dict | str:
        """Pre-execution governance. Returns {} on allow, denial string on deny."""
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

        # Increment attempts BEFORE governance
        await self._session.increment_attempts()

        # Start OTel span
        span = self._guard.telemetry.start_tool_span(envelope)

        try:
            # Run pipeline
            decision = await self._pipeline.pre_execute(envelope, self._session)
            await self._emit_workflow_events(envelope, decision.workflow_events)

            # Handle observe mode: convert deny to allow with warning
            if self._guard.mode == "observe" and decision.action == "deny":
                await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_WOULD_DENY)
                span.set_attribute("governance.action", "would_deny")
                span.set_attribute("governance.would_deny_reason", decision.reason)
                self._pending[call_id] = (envelope, span)
                self._pending_decisions[call_id] = decision
                return {}  # allow through

            # Handle deny
            if decision.action == "deny":
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
                denied, decision = await self._resolve_pending_approval(envelope, decision, span)
                if denied is not None:
                    self._pending.pop(call_id, None)
                    self._pending_decisions.pop(call_id, None)
                    return denied

            # Handle per-contract observed denials
            if decision.observed:
                for cr in decision.contracts_evaluated:
                    if cr.get("observed") and not cr.get("passed"):
                        await self._guard.audit_sink.emit(
                            AuditEvent(
                                action=AuditAction.CALL_WOULD_DENY,
                                run_id=envelope.run_id,
                                call_id=envelope.call_id,
                                call_index=envelope.call_index,
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

            # Handle allow
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

    async def _post(
        self, call_id: str, tool_response: Any = None, *, tool_success: bool | None = None
    ) -> PostCallResult:
        """Post-execution governance. Returns PostCallResult with findings."""
        pending = self._pending.pop(call_id, None)
        if not pending:
            return PostCallResult(result=tool_response)

        decision = self._pending_decisions.pop(call_id, None)
        if decision is None:
            return PostCallResult(result=tool_response)

        envelope, span = pending

        try:
            # Derive tool_success from response if not explicitly provided
            if tool_success is None:
                tool_success = self._check_tool_success(envelope.tool_name, tool_response)

            # Run pipeline
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

            # Record in session
            await self._session.record_execution(envelope.tool_name, success=tool_success)

            # Emit audit
            action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
            await self._guard.audit_sink.emit(
                AuditEvent(
                    action=action,
                    run_id=envelope.run_id,
                    call_id=envelope.call_id,
                    call_index=envelope.call_index,
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
            findings=findings,
        )

    async def _emit_audit_pre(self, envelope, decision, audit_action=None):
        if audit_action is None:
            audit_action = AuditAction.CALL_DENIED if decision.action == "deny" else AuditAction.CALL_ALLOWED

        await self._guard.audit_sink.emit(
            AuditEvent(
                action=audit_action,
                run_id=envelope.run_id,
                call_id=envelope.call_id,
                call_index=envelope.call_index,
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
            denied = await self._handle_approval(envelope, current, span)
            if denied is not None:
                return denied, current
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
            timeout_effect=decision.approval_timeout_effect,
            principal=principal_dict,
        )
        await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_APPROVAL_REQUESTED)

        approval_decision = await self._guard._approval_backend.wait_for_decision(
            approval_id=approval_request.approval_id,
            timeout=decision.approval_timeout,
        )

        approved = approval_decision.approved
        if not approved and approval_decision.status == ApprovalStatus.TIMEOUT:
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_APPROVAL_TIMEOUT)
            if decision.approval_timeout_effect == "allow":
                approved = True
        elif approval_decision.approved:
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_APPROVAL_GRANTED)
        else:
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_APPROVAL_DENIED)

        if approved:
            span.set_attribute("governance.action", "approved")
            return None

        reason = approval_decision.reason or decision.reason or "Approval denied"
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
        return self._deny(f"Approval denied: {reason}")

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

    def _deny(self, reason: str) -> str:
        return f"DENIED: {reason}"

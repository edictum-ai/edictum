"""Execution logic for Edictum.run() — governance pipeline with tool execution."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from edictum._exceptions import EdictumDenied, EdictumToolError
from edictum.approval import ApprovalStatus
from edictum.audit import AuditAction, AuditEvent
from edictum.envelope import create_envelope
from edictum.otel import has_otel
from edictum.pipeline import CheckPipeline, PreDecision
from edictum.session import Session

if TYPE_CHECKING:
    from edictum._guard import Edictum

logger = logging.getLogger(__name__)

_ERROR_ACTIONS = frozenset({"call_denied", "call_approval_denied", "call_approval_timeout"})
_MAX_WORKFLOW_APPROVAL_ROUNDS = 32


def _default_success_check(tool_name: str, result: Any) -> bool:
    """Default heuristic for tool success detection.

    Matches the heuristic used by all framework adapters: None is success,
    dict with is_error is failure, string starting with error:/fatal: is failure.
    """
    if result is None:
        return True
    if isinstance(result, dict):
        if result.get("is_error"):
            return False
    if isinstance(result, str):
        lower = result[:7].lower()
        if lower.startswith("error:") or lower.startswith("fatal:"):
            return False
    return True


async def _run(
    self: Edictum,
    tool_name: str,
    args: dict[str, Any],
    tool_callable: Callable,
    *,
    session_id: str | None = None,
    **envelope_kwargs,
) -> Any:
    """Framework-agnostic entrypoint."""
    session_id = session_id or self._session_id
    session = Session(session_id, self.backend)
    pipeline = CheckPipeline(self)

    # Allow per-call environment override; fall back to guard-level default
    env = envelope_kwargs.pop("environment", self.environment)

    # Resolve principal: per-call resolver > static > envelope_kwargs
    if "principal" not in envelope_kwargs:
        resolved = self._resolve_principal(tool_name, args)
        if resolved is not None:
            envelope_kwargs["principal"] = resolved

    envelope = create_envelope(
        tool_name=tool_name,
        tool_input=args,
        run_id=session_id,
        environment=env,
        registry=self.tool_registry,
        **envelope_kwargs,
    )

    # Increment attempts
    await session.increment_attempts()

    # Start OTel span
    span = self.telemetry.start_tool_span(envelope)
    try:
        if self.policy_version:
            span.set_attribute("edictum.policy_version", self.policy_version)

        # Pre-execute
        pre = await pipeline.pre_execute(envelope, session)
        await _emit_workflow_events(self, envelope, pre.workflow_events)

        # Handle pending_approval: request approval from backend
        if pre.action == "pending_approval":
            approved, decision, pre = await _resolve_pending_approval(
                self,
                pipeline,
                session,
                envelope,
                pre,
            )
            if not approved:
                self.telemetry.record_denial(envelope, decision.reason or pre.reason)
                if self._on_deny:
                    try:
                        self._on_deny(envelope, decision.reason or pre.reason or "", pre.decision_name)
                    except Exception:
                        logger.exception("on_deny callback raised")
                span.set_attribute("governance.action", "denied")
                span.set_attribute("governance.reason", decision.reason or pre.reason or "")
                self.telemetry.set_span_error(span, decision.reason or pre.reason or "denied")
                raise EdictumDenied(
                    reason=decision.reason or pre.reason,
                    decision_source=pre.decision_source,
                    decision_name=pre.decision_name,
                )
            if pre.action == "pending_approval":
                self.telemetry.record_allowed(envelope)
                if self._on_allow:
                    try:
                        self._on_allow(envelope)
                    except Exception:
                        logger.exception("on_allow callback raised")
                span_action = "approved"
                if decision.status == ApprovalStatus.TIMEOUT and pre.approval_timeout_action == "allow":
                    span_action = "timeout_allow"
                span.set_attribute("governance.action", span_action)

        # Determine if this is a real block or just per-rule observed blocks
        real_deny = pre.action == "block" and not pre.observed

        # Skip pre-execution audit for approval-granted path (already handled above)
        if pre.action == "pending_approval":
            pass  # Fall through directly to tool execution
        elif real_deny:
            audit_action = AuditAction.CALL_WOULD_DENY if self.mode == "observe" else AuditAction.CALL_DENIED
            await _emit_run_pre_audit(self, envelope, session, audit_action, pre)
            self.telemetry.record_denial(envelope, pre.reason)
            if self.mode == "enforce":
                if self._on_deny:
                    try:
                        self._on_deny(envelope, pre.reason or "", pre.decision_name)
                    except Exception:
                        logger.exception("on_deny callback raised")
                span.set_attribute("governance.action", "denied")
                span.set_attribute("governance.reason", pre.reason or "")
                self.telemetry.set_span_error(span, pre.reason or "denied")
                raise EdictumDenied(
                    reason=pre.reason,
                    decision_source=pre.decision_source,
                    decision_name=pre.decision_name,
                )
            # observe mode: fall through to execute
            span.set_attribute("governance.action", "would_deny")
            span.set_attribute("governance.would_deny_reason", pre.reason or "")
        else:
            # Emit CALL_WOULD_DENY for any per-rule observed blocks
            for cr in pre.contracts_evaluated:
                if cr.get("observed") and not cr.get("passed"):
                    observed_event = AuditEvent(
                        action=AuditAction.CALL_WOULD_DENY,
                        run_id=envelope.run_id,
                        call_id=envelope.call_id,
                        tool_name=envelope.tool_name,
                        tool_args=self.redaction.redact_args(envelope.args),
                        side_effect=envelope.side_effect.value,
                        environment=envelope.environment,
                        principal=asdict(envelope.principal) if envelope.principal else None,
                        decision_source="precondition",
                        decision_name=cr["name"],
                        reason=cr["message"],
                        mode="observe",
                        policy_version=self.policy_version,
                        policy_error=pre.policy_error,
                    )
                    await self.audit_sink.emit(observed_event)
                    _emit_otel_governance_span(self, observed_event)
            await _emit_run_pre_audit(self, envelope, session, AuditAction.CALL_ALLOWED, pre)
            self.telemetry.record_allowed(envelope)
            if self._on_allow:
                try:
                    self._on_allow(envelope)
                except Exception:
                    logger.exception("on_allow callback raised")
            span.set_attribute("governance.action", "allowed")

        # Emit observe-mode audit events (never affect the real decision)
        for sr in pre.observe_results:
            observe_action = AuditAction.CALL_WOULD_DENY if not sr["passed"] else AuditAction.CALL_ALLOWED
            observe_event = AuditEvent(
                action=observe_action,
                run_id=envelope.run_id,
                call_id=envelope.call_id,
                tool_name=envelope.tool_name,
                tool_args=self.redaction.redact_args(envelope.args),
                side_effect=envelope.side_effect.value,
                environment=envelope.environment,
                principal=asdict(envelope.principal) if envelope.principal else None,
                decision_source=sr["source"],
                decision_name=sr["name"],
                reason=sr["message"],
                mode="observe",
                policy_version=self.policy_version,
            )
            await self.audit_sink.emit(observe_event)
            _emit_otel_governance_span(self, observe_event)

        # Execute tool
        try:
            result = tool_callable(**args)
            if asyncio.iscoroutine(result):
                result = await result
            if self._success_check:
                tool_success = self._success_check(tool_name, result)
            else:
                tool_success = _default_success_check(tool_name, result)
        except Exception as e:
            result = str(e)
            tool_success = False

        # Post-execute
        post = await pipeline.post_execute(envelope, result, tool_success)
        workflow_events: list[dict[str, Any]] = []
        if tool_success and pre.workflow_involved and pre.workflow_stage_id and self._workflow_runtime is not None:
            workflow_events = await self._workflow_runtime.record_result(
                session,
                pre.workflow_stage_id,
                envelope,
            )
        await session.record_execution(tool_name, success=tool_success)

        # Emit post-execute audit
        post_action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
        post_event = AuditEvent(
            action=post_action,
            run_id=envelope.run_id,
            call_id=envelope.call_id,
            tool_name=envelope.tool_name,
            tool_args=self.redaction.redact_args(envelope.args),
            side_effect=envelope.side_effect.value,
            environment=envelope.environment,
            principal=asdict(envelope.principal) if envelope.principal else None,
            tool_success=tool_success,
            postconditions_passed=post.postconditions_passed,
            contracts_evaluated=post.contracts_evaluated,
            session_attempt_count=await session.attempt_count(),
            session_execution_count=await session.execution_count(),
            mode=self.mode,
            policy_version=self.policy_version,
            policy_error=post.policy_error,
            workflow=pre.workflow,
        )
        await self.audit_sink.emit(post_event)
        _emit_otel_governance_span(self, post_event)
        await _emit_workflow_events(self, envelope, workflow_events)

        span.set_attribute("governance.tool_success", tool_success)
        span.set_attribute("governance.postconditions_passed", post.postconditions_passed)

        if tool_success:
            self.telemetry.set_span_ok(span)
        else:
            self.telemetry.set_span_error(span, "tool execution failed")

        if not tool_success:
            raise EdictumToolError(result)

        return post.redacted_response if post.redacted_response is not None else result
    finally:
        span.end()


async def _emit_run_pre_audit(self: Edictum, envelope, session, action: AuditAction, pre: PreDecision) -> None:
    event = AuditEvent(
        action=action,
        run_id=envelope.run_id,
        call_id=envelope.call_id,
        tool_name=envelope.tool_name,
        tool_args=self.redaction.redact_args(envelope.args),
        side_effect=envelope.side_effect.value,
        environment=envelope.environment,
        principal=asdict(envelope.principal) if envelope.principal else None,
        decision_source=pre.decision_source,
        decision_name=pre.decision_name,
        reason=pre.reason,
        hooks_evaluated=pre.hooks_evaluated,
        contracts_evaluated=pre.contracts_evaluated,
        session_attempt_count=await session.attempt_count(),
        session_execution_count=await session.execution_count(),
        mode=self.mode,
        policy_version=self.policy_version,
        policy_error=pre.policy_error,
        workflow=pre.workflow,
    )
    await self.audit_sink.emit(event)
    _emit_otel_governance_span(self, event)


async def _resolve_pending_approval(
    self: Edictum,
    pipeline: CheckPipeline,
    session: Session,
    envelope,
    pre: PreDecision,
):
    if self._approval_backend is None:
        await _emit_run_pre_audit(self, envelope, session, AuditAction.CALL_DENIED, pre)
        raise EdictumDenied(
            reason=f"Approval required but no approval backend configured: {pre.reason}",
            decision_source=pre.decision_source,
            decision_name=pre.decision_name,
        )

    current = pre
    for _ in range(_MAX_WORKFLOW_APPROVAL_ROUNDS):
        principal_dict = asdict(envelope.principal) if envelope.principal else None
        approval_request = await self._approval_backend.request_approval(
            tool_name=envelope.tool_name,
            tool_args=envelope.args,
            message=current.approval_message or current.reason or "",
            timeout=current.approval_timeout,
            timeout_action=current.approval_timeout_action,
            principal=principal_dict,
        )
        await _emit_run_pre_audit(self, envelope, session, AuditAction.CALL_APPROVAL_REQUESTED, current)
        decision = await self._approval_backend.wait_for_decision(
            approval_id=approval_request.approval_id,
            timeout=current.approval_timeout,
        )
        approved = False
        if decision.status == ApprovalStatus.TIMEOUT:
            await _emit_run_pre_audit(self, envelope, session, AuditAction.CALL_APPROVAL_TIMEOUT, current)
            if current.approval_timeout_action == "allow":
                approved = True
        elif decision.approved:
            await _emit_run_pre_audit(self, envelope, session, AuditAction.CALL_APPROVAL_GRANTED, current)
            approved = True
        else:
            await _emit_run_pre_audit(self, envelope, session, AuditAction.CALL_APPROVAL_DENIED, current)

        if not approved:
            return False, decision, current

        if current.decision_source != "workflow" or not current.workflow_stage_id or self._workflow_runtime is None:
            return True, decision, current

        await self._workflow_runtime.record_approval(session, current.workflow_stage_id)
        current = await pipeline.pre_execute(envelope, session)
        await _emit_workflow_events(self, envelope, current.workflow_events)
        if current.action != "pending_approval":
            return True, decision, current

    raise RuntimeError(f"workflow: exceeded maximum approval rounds ({_MAX_WORKFLOW_APPROVAL_ROUNDS})")


async def _emit_workflow_events(self: Edictum, envelope, events: list[dict[str, Any]]) -> None:
    for record in events:
        workflow = record.get("workflow")
        action_name = record.get("action")
        if not isinstance(workflow, dict) or not isinstance(action_name, str):
            continue
        event = AuditEvent(
            action=AuditAction.WORKFLOW_STAGE_ADVANCED,
            run_id=envelope.run_id,
            call_id=envelope.call_id,
            tool_name=envelope.tool_name,
            tool_args=self.redaction.redact_args(envelope.args),
            side_effect=envelope.side_effect.value,
            environment=envelope.environment,
            principal=asdict(envelope.principal) if envelope.principal else None,
            mode=self.mode,
            policy_version=self.policy_version,
            workflow=dict(workflow),
        )
        if action_name == AuditAction.WORKFLOW_COMPLETED.value:
            event.action = AuditAction.WORKFLOW_COMPLETED
        await self.audit_sink.emit(event)
        _emit_otel_governance_span(self, event)


def _emit_otel_governance_span(self: Edictum, audit_event: AuditEvent) -> None:
    """Emit an OTel span with governance attributes from an AuditEvent."""
    if not has_otel():
        return

    from opentelemetry.trace import StatusCode

    with self._gov_tracer.start_as_current_span("edictum.evaluate") as span:
        span.set_attribute("edictum.tool.name", audit_event.tool_name)
        span.set_attribute("edictum.decision", audit_event.action.value)
        span.set_attribute("edictum.decision.reason", audit_event.reason or "")
        span.set_attribute("edictum.decision.source", audit_event.decision_source or "")
        span.set_attribute("edictum.decision.name", audit_event.decision_name or "")
        span.set_attribute("edictum.side_effect", audit_event.side_effect)
        span.set_attribute("edictum.environment", audit_event.environment)
        span.set_attribute("edictum.mode", audit_event.mode)
        span.set_attribute("edictum.session.attempt_count", audit_event.session_attempt_count or 0)
        span.set_attribute("edictum.session.execution_count", audit_event.session_execution_count or 0)

        tool_args_str = json.dumps(audit_event.tool_args, default=str) if audit_event.tool_args else "{}"
        span.set_attribute("edictum.tool.args", tool_args_str)

        if audit_event.principal:
            for key in ("role", "ticket_ref", "user_id", "org_id"):
                val = audit_event.principal.get(key)
                if val:
                    span.set_attribute(f"edictum.principal.{key}", val)

        if audit_event.policy_version:
            span.set_attribute("edictum.policy_version", audit_event.policy_version)
        if audit_event.policy_error:
            span.set_attribute("edictum.policy_error", True)

        if audit_event.action.value in _ERROR_ACTIONS:
            span.set_status(StatusCode.ERROR, audit_event.reason or "denied")
        else:
            span.set_status(StatusCode.OK)

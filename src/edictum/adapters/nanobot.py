"""Nanobot adapter — ruled ToolRegistry for multi-channel AI agents."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict, replace
from typing import TYPE_CHECKING, Any

from edictum.approval import ApprovalStatus, _request_approval_with_session_compat
from edictum.audit import AuditAction, AuditEvent
from edictum.envelope import Principal, create_envelope
from edictum.pipeline import CheckPipeline
from edictum.session import Session, validate_session_id
from edictum.workflow.state import build_workflow_snapshot

logger = logging.getLogger(__name__)
_MAX_WORKFLOW_APPROVAL_ROUNDS = 32

if TYPE_CHECKING:
    from edictum import Edictum


class GovernedToolRegistry:
    """Drop-in replacement for nanobot's ToolRegistry with Edictum rules.

    Wraps every tool execution with pre/post rule checks.
    Used by swapping into AgentLoop.__init__().
    """

    def __init__(
        self,
        inner: Any,
        guard: Edictum,
        *,
        session_id: str | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    ) -> None:
        self._inner = inner
        self._guard = guard
        self._pipeline = CheckPipeline(guard)
        self._session_id = session_id or str(uuid.uuid4())
        self._session = Session(self._session_id, guard.backend)
        self._call_index = 0
        self._principal = principal
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

    # -- Delegate ToolRegistry methods to inner --

    def register(self, name: str, handler: Callable, description: str = "") -> None:
        self._inner.register(name, handler, description)

    def list_tools(self) -> list[str]:
        return list(self._inner.list_tools())

    def get_description(self, name: str) -> str:
        return str(self._inner.get_description(name))

    async def execute(self, name: str, args: dict) -> str:
        """Execute a tool with rule wrapping.

        Returns a string result. Blocks reuse the adapter's existing marker
        so the LLM can see the reason and adjust.
        """
        call_id = str(uuid.uuid4())
        parent_session_id = self._audit_parent_session_id()

        envelope = create_envelope(
            tool_name=name,
            tool_input=args,
            run_id=self._session_id,
            call_index=self._call_index,
            tool_use_id=call_id,
            environment=self._guard.environment,
            registry=self._guard.tool_registry,
            principal=self._resolve_principal(name, args),
            metadata=({"parent_session_id": parent_session_id} if parent_session_id is not None else {}),
        )
        self._call_index += 1

        await self._session.increment_attempts()

        span = self._guard.telemetry.start_tool_span(envelope)

        try:
            decision = await self._pipeline.pre_execute(envelope, self._session)
            await self._emit_workflow_events(envelope, decision.workflow_events)

            # Observe mode: convert block to allow with CALL_WOULD_DENY audit
            if self._guard.mode == "observe" and decision.action == "block":
                await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_WOULD_DENY)
                span.set_attribute("governance.action", "would_deny")
                span.set_attribute("governance.would_deny_reason", decision.reason)
                # Fall through to execute
            elif decision.action == "block":
                # Enforce mode: return a blocked marker string.
                await self._emit_audit_pre(envelope, decision)
                self._guard.telemetry.record_denial(envelope, decision.reason)
                if self._guard._on_deny:
                    try:
                        self._guard._on_deny(envelope, decision.reason or "", decision.decision_name)
                    except Exception:
                        logger.exception("on_deny callback raised")
                span.set_attribute("governance.action", "denied")
                self._guard.telemetry.set_span_error(span, decision.reason or "denied")
                return f"[DENIED] {decision.reason}"
            elif decision.action == "pending_approval":
                # Approval flow
                result, decision = await self._resolve_pending_approval(envelope, decision, span)
                if result is not None:
                    return result
                # Approved — fall through to execute
            else:
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
                                    parent_session_id=parent_session_id,
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

            # Execute the tool via inner registry
            result = await self._inner.execute(name, args)

            # Post-execution rule evaluation
            tool_success = self._check_tool_success(name, result)
            post_decision = await self._pipeline.post_execute(envelope, result, tool_success)

            effective_response = (
                post_decision.redacted_response if post_decision.redacted_response is not None else result
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
            workflow = decision.workflow
            if decision.workflow_involved and self._guard._workflow_runtime is not None:
                workflow_state = await self._guard._workflow_runtime.state(self._session)
                workflow = build_workflow_snapshot(self._guard._workflow_runtime.definition, workflow_state)

            await self._session.record_execution(name, success=tool_success)

            action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
            await self._guard.audit_sink.emit(
                AuditEvent(
                    action=action,
                    run_id=envelope.run_id,
                    call_id=envelope.call_id,
                    call_index=envelope.call_index,
                    session_id=self._session_id,
                    parent_session_id=parent_session_id,
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
                    workflow=workflow,
                )
            )
            await self._emit_workflow_events(envelope, workflow_events)

            span.set_attribute("governance.tool_success", tool_success)
            span.set_attribute("governance.postconditions_passed", post_decision.postconditions_passed)

            if tool_success:
                self._guard.telemetry.set_span_ok(span)
            else:
                self._guard.telemetry.set_span_error(span, "tool execution failed")

            return str(effective_response)
        finally:
            span.end()

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
        """Handle one pending_approval decision. Returns denial string or None to proceed."""
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
            return f"[DENIED] {reason}"

        principal_dict = asdict(envelope.principal) if envelope.principal else None
        approval_request = await _request_approval_with_session_compat(
            self._guard._approval_backend,
            tool_name=envelope.tool_name,
            tool_args=envelope.args,
            message=decision.approval_message or decision.reason or "",
            timeout=decision.approval_timeout,
            timeout_action=decision.approval_timeout_action,
            principal=principal_dict,
            session_id=self._session_id,
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
            return None  # Proceed with execution

        reason = approval_decision.reason or decision.reason or "Approval blocked"
        self._guard.telemetry.record_denial(envelope, reason)
        if self._guard._on_deny:
            try:
                self._guard._on_deny(envelope, reason, decision.decision_name)
            except Exception:
                logger.exception("on_deny callback raised")
        span.set_attribute("governance.action", "denied")
        self._guard.telemetry.set_span_error(span, reason)
        return f"[DENIED] Approval blocked: {reason}"

    async def _emit_workflow_events(self, envelope: Any, events: list[dict]) -> None:
        for record in events:
            workflow = record.get("workflow")
            action_name = record.get("action")
            if not isinstance(workflow, dict) or not isinstance(action_name, str):
                continue
            action = AuditAction.WORKFLOW_STAGE_ADVANCED
            if action_name == AuditAction.WORKFLOW_COMPLETED.value:
                action = AuditAction.WORKFLOW_COMPLETED
            elif action_name == AuditAction.WORKFLOW_STATE_UPDATED.value:
                action = AuditAction.WORKFLOW_STATE_UPDATED
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

    def _check_tool_success(self, tool_name: str, result: Any) -> bool:
        if self._guard._success_check is not None:
            return bool(self._guard._success_check(tool_name, result))
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

    def for_subagent(
        self,
        *,
        session_id: str | None = None,
    ) -> GovernedToolRegistry:
        """Create a child GovernedToolRegistry for a sub-agent.

        Shares the same guard and inner registry but gets its own session.
        Used by SubagentManager to propagate rule evaluation to child agents.
        """
        child = GovernedToolRegistry(
            inner=self._inner,
            guard=self._guard,
            session_id=session_id,
            principal=self._principal,
            principal_resolver=self._principal_resolver,
        )
        child._parent_session_id = self._session_id
        return child


class NanobotAdapter:
    """Adapter for integrating Edictum rules with nanobot agents.

    Usage::

        adapter = NanobotAdapter(guard)
        governed_registry = adapter.wrap_registry(agent.tool_registry)
        # Replace agent's registry with the governed one
    """

    def __init__(
        self,
        guard: Edictum,
        *,
        session_id: str | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
    ) -> None:
        self._guard = guard
        self._session_id = session_id
        self._principal = principal
        self._principal_resolver = principal_resolver

    def wrap_registry(self, registry: Any) -> GovernedToolRegistry:
        """Wrap a nanobot ToolRegistry with rule evaluation.

        Returns a GovernedToolRegistry that can be used as a drop-in
        replacement for the original.
        """
        return GovernedToolRegistry(
            inner=registry,
            guard=self._guard,
            session_id=self._session_id,
            principal=self._principal,
            principal_resolver=self._principal_resolver,
        )

    @staticmethod
    def principal_from_message(message: Any) -> Principal:
        """Map a nanobot InboundMessage to an edictum Principal.

        Maps channel + sender_id to Principal fields:
        - user_id = "{channel}:{sender_id}"
        - role = "user" (default, can be overridden)
        - claims = {"channel": channel, "channel_id": channel_id}
        """
        return Principal(
            user_id=f"{message.channel}:{message.sender_id}",
            role="user",
            claims={
                "channel": message.channel,
                "channel_id": getattr(message, "channel_id", ""),
            },
        )

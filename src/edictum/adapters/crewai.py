"""CrewAI adapter -- global before/after hook integration."""

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
from edictum.pipeline import CheckPipeline
from edictum.session import Session, validate_session_id
from edictum.workflow.state import build_workflow_snapshot

logger = logging.getLogger(__name__)
_MAX_WORKFLOW_APPROVAL_ROUNDS = 32

if TYPE_CHECKING:
    from edictum import Edictum


class CrewAIAdapter:
    """Translate Edictum pipeline decisions into CrewAI hook format.

    The adapter does NOT contain governance logic -- that lives in
    CheckPipeline. The adapter only:
    1. Creates envelopes from CrewAI hook context
    2. Manages pending state (envelope + span) between before/after hooks
    3. Translates PreDecision/PostDecision into CrewAI hook responses
    4. Handles observe mode (block -> allow conversion)

    CrewAI is sequential, so a single-pending slot correlates before/after.
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
        self._pending_envelope: Any | None = None
        self._pending_span: Any | None = None
        self._pending_decision: Any | None = None
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

    @staticmethod
    def _normalize_tool_name(name: str) -> str:
        """Normalize CrewAI tool names to match rule names.

        Lowercases and replaces spaces, hyphens, and other non-alphanumeric
        separators with underscores, then collapses consecutive underscores.

        Examples:
            "Search Documents" -> "search_documents"
            "Read-Database"    -> "read_database"
            "already_snake"       -> "already_snake"
        """
        import re

        return re.sub(r"_+", "_", re.sub(r"[\s\-]+", "_", name.lower())).strip("_")

    def register(
        self,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> None:
        """Register global before/after tool-call hooks with CrewAI.

        Uses CrewAI's ``register_*_hook()`` functions instead of decorators
        to avoid ``setattr`` failures on bound methods.

        Args:
            on_postcondition_warn: Optional callback invoked when postconditions
                detect issues. Receives (original_result, violations) and is called
                for side effects (CrewAI controls the tool result flow).

        Imports CrewAI hook registration lazily to avoid hard dependency.
        The underlying handlers are stored as _before_hook/_after_hook for
        direct test access without requiring the CrewAI framework.
        """
        self._on_postcondition_warn = on_postcondition_warn

        from crewai.hooks.tool_hooks import (
            register_after_tool_call_hook,
            register_before_tool_call_hook,
        )

        adapter = self

        def _run_async(coro):
            """Bridge async coroutine to sync CrewAI hook context.

            CrewAI calls hooks synchronously, but Edictum's guard is async.
            When no event loop is running, ``asyncio.run()`` is used directly.
            When called from within an active loop (e.g. nested in an async
            framework), a worker thread runs a fresh loop to avoid blocking
            the caller's loop.  This means Edictum state accessed inside the
            coroutine must be thread-safe; the adapter's own state is guarded
            by CrewAI's sequential-execution model (one tool at a time).
            """
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(asyncio.run, coro)
                    return future.result()
            return asyncio.run(coro)

        def before_hook(context):
            original_name = context.tool_name
            context.tool_name = adapter._normalize_tool_name(original_name)
            result = _run_async(adapter._before_hook(context))
            context.tool_name = original_name
            return result

        def after_hook(context):
            original_name = context.tool_name
            context.tool_name = adapter._normalize_tool_name(original_name)
            _run_async(adapter._after_hook(context))
            context.tool_name = original_name
            return None  # keep original result

        register_before_tool_call_hook(before_hook)
        register_after_tool_call_hook(after_hook)

    async def _before_hook(self, context: Any) -> str | None:
        """Handle a before-tool-call event from CrewAI.

        Returns `None` to allow or a string marker to block execution.
        """
        tool_name: str = context.tool_name
        tool_input: dict = context.tool_input
        call_id = str(uuid.uuid4())

        # Create envelope
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

        # Run pipeline
        try:
            decision = await self._pipeline.pre_execute(envelope, self._session)
            await self._emit_workflow_events(envelope, decision.workflow_events)

            # Handle observe mode: convert block to allow with warning
            if self._guard.mode == "observe" and decision.action == "block":
                await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_WOULD_DENY)
                span.set_attribute("governance.action", "would_deny")
                span.set_attribute("governance.would_deny_reason", decision.reason)
                self._pending_envelope = envelope
                self._pending_span = span
                self._pending_decision = decision
                return None  # allow through

            # Handle block
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
                self._pending_envelope = None
                self._pending_span = None
                self._pending_decision = None
                return self._deny(decision.reason or "")

            if decision.action == "pending_approval":
                blocked_result, decision = await self._resolve_pending_approval(envelope, decision, span)
                if blocked_result is not None:
                    span.end()
                    self._pending_envelope = None
                    self._pending_span = None
                    self._pending_decision = None
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

            # Handle allow
            await self._emit_audit_pre(envelope, decision)
            if self._guard._on_allow:
                try:
                    self._guard._on_allow(envelope)
                except Exception:
                    logger.exception("on_allow callback raised")
            span.set_attribute("governance.action", "allowed")
            self._pending_envelope = envelope
            self._pending_span = span
            self._pending_decision = decision
            return None
        except Exception:
            if self._pending_span is not span:
                span.end()
            raise

    async def _after_hook(self, context: Any) -> PostCallResult | None:
        """Handle an after-tool-call event from CrewAI. Returns PostCallResult."""
        # Use single-pending slot (sequential execution model)
        envelope = self._pending_envelope
        span = self._pending_span
        decision = self._pending_decision

        if envelope is None or span is None or decision is None:
            return None

        # Clear pending state
        self._pending_envelope = None
        self._pending_span = None
        self._pending_decision = None

        try:
            # Derive tool_success from context
            tool_result = getattr(context, "tool_result", None)
            tool_success = self._check_tool_success(envelope.tool_name, tool_result)

            # Run pipeline
            post_decision = await self._pipeline.post_execute(envelope, tool_result, tool_success)

            effective_response = (
                post_decision.redacted_response if post_decision.redacted_response is not None else tool_result
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
        finally:
            span.end()

        # Build violations
        violations = build_findings(post_decision)
        post_result = PostCallResult(
            result=effective_response,
            postconditions_passed=post_decision.postconditions_passed,
            violations=violations,
        )

        # Call callback for side effects
        on_warn = getattr(self, "_on_postcondition_warn", None)
        if not post_result.postconditions_passed and on_warn:
            try:
                on_warn(post_result.result, post_result.violations)
            except Exception:
                logger.exception("on_postcondition_warn callback raised")

        return post_result

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
        return self._deny(f"Approval blocked: {reason}")

    def _check_tool_success(self, tool_name: str, tool_result: Any) -> bool:
        if self._guard._success_check is not None:
            return bool(self._guard._success_check(tool_name, tool_result))
        if tool_result is None:
            return True
        if isinstance(tool_result, dict):
            if tool_result.get("is_error"):
                return False
        if isinstance(tool_result, str):
            lower = tool_result[:7].lower()
            if lower.startswith("error:") or lower.startswith("fatal:"):
                return False
        return True

    @staticmethod
    def _deny(reason: str) -> str:
        """Return denial reason string."""
        return f"DENIED: {reason}"

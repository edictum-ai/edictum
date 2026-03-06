"""Google ADK adapter -- plugin and agent callback integration for tool governance."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from edictum.approval import ApprovalStatus
from edictum.audit import AuditAction, AuditEvent
from edictum.envelope import Principal, create_envelope
from edictum.findings import Finding, PostCallResult, build_findings
from edictum.pipeline import GovernancePipeline
from edictum.session import Session

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from edictum import Edictum


class GoogleADKAdapter:
    """Translate Edictum pipeline decisions into Google ADK plugin/callback format.

    The adapter does NOT contain governance logic -- that lives in
    GovernancePipeline. The adapter only:
    1. Creates envelopes from ADK tool callback data
    2. Manages pending state (envelope + span) between before/after
    3. Translates PreDecision/PostDecision into ADK return format
    4. Handles observe mode (deny -> allow conversion)

    Two integration paths:

    - ``as_plugin()`` returns a BasePlugin for Runner(plugins=[...]).
      Applies governance globally to ALL agents/tools. Recommended path.
      Note: Plugins are NOT invoked in ADK's live/streaming mode.

    - ``as_agent_callbacks()`` returns (before_cb, after_cb, error_cb) for LlmAgent.
      Use for per-agent scoping or live/streaming mode governance.
    """

    def __init__(
        self,
        guard: Edictum,
        session_id: str | None = None,
        principal: Principal | None = None,
        principal_resolver: Callable[[str, dict[str, Any]], Principal] | None = None,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ):
        self._guard = guard
        self._pipeline = GovernancePipeline(guard)
        self._session_id = session_id or str(uuid.uuid4())
        self._session = Session(self._session_id, guard.backend)
        self._call_index = 0
        self._pending: dict[str, tuple[Any, Any]] = {}
        self._principal = principal
        self._principal_resolver = principal_resolver
        self._on_postcondition_warn = on_postcondition_warn

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

    async def _pre(
        self,
        tool_name: str,
        tool_input: dict,
        call_id: str,
        tool_context: Any = None,
    ) -> dict | None:
        """Run pre-execution governance. Returns denial dict or None to allow.

        Exposed for direct testing without framework imports.
        """
        # Resolve principal -- auto-resolve from tool_context when no explicit principal/resolver
        principal = self._resolve_principal(tool_name, tool_input)
        if principal is None and tool_context is not None:
            user_id = getattr(tool_context, "user_id", None)
            agent_name = getattr(tool_context, "agent_name", None)
            if user_id or agent_name:
                principal = Principal(
                    user_id=user_id,
                    claims={"adk_agent_name": agent_name} if agent_name else {},
                )

        # Extract ADK-specific metadata
        metadata: dict[str, Any] = {}
        if tool_context is not None:
            invocation_id = getattr(tool_context, "invocation_id", None)
            agent_name = getattr(tool_context, "agent_name", None)
            if invocation_id:
                metadata["adk_invocation_id"] = invocation_id
            if agent_name:
                metadata["adk_agent_name"] = agent_name

        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=tool_input,
            run_id=self._session_id,
            call_index=self._call_index,
            tool_use_id=call_id,
            environment=self._guard.environment,
            registry=self._guard.tool_registry,
            principal=principal,
            metadata=metadata,
        )
        self._call_index += 1

        # Increment attempts BEFORE governance
        await self._session.increment_attempts()

        # Start OTel span
        span = self._guard.telemetry.start_tool_span(envelope)

        try:
            # Run pipeline
            decision = await self._pipeline.pre_execute(envelope, self._session)
        except Exception:
            span.end()
            raise

        # Handle observe mode: convert deny to allow with warning
        if self._guard.mode == "observe" and decision.action == "deny":
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_WOULD_DENY)
            span.set_attribute("governance.action", "would_deny")
            span.set_attribute("governance.would_deny_reason", decision.reason)
            self._pending[call_id] = (envelope, span)
            return None  # allow through

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
            span.end()
            self._pending.pop(call_id, None)
            return self._deny(decision.reason or "")

        # Handle pending_approval
        if decision.action == "pending_approval":
            result = await self._handle_approval(envelope, decision, span)
            if result is not None:
                return result
            # Approved -- fall through to allow
            self._pending[call_id] = (envelope, span)
            return None

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
        return None

    async def _post(self, call_id: str, tool_response: Any = None) -> PostCallResult:
        """Run post-execution governance. Returns PostCallResult with findings.

        Exposed for direct testing without framework imports.
        """
        pending = self._pending.pop(call_id, None) if call_id else None
        if not pending:
            return PostCallResult(result=tool_response)

        envelope, span = pending

        try:
            # Derive tool_success from response
            tool_success = self._check_tool_success(envelope.tool_name, tool_response)

            # Run pipeline
            post_decision = await self._pipeline.post_execute(envelope, tool_response, tool_success)

            effective_response = (
                post_decision.redacted_response if post_decision.redacted_response is not None else tool_response
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
                )
            )

            # End span
            span.set_attribute("governance.tool_success", tool_success)
            span.set_attribute("governance.postconditions_passed", post_decision.postconditions_passed)
        finally:
            span.end()

        findings = build_findings(post_decision)
        post_result = PostCallResult(
            result=effective_response,
            postconditions_passed=post_decision.postconditions_passed,
            findings=findings,
            output_suppressed=post_decision.output_suppressed,
        )

        # Call callback for side effects
        on_warn = getattr(self, "_on_postcondition_warn", None)
        if not post_result.postconditions_passed and on_warn:
            try:
                on_warn(post_result.result, post_result.findings)
            except Exception:
                logger.exception("on_postcondition_warn callback raised")

        return post_result

    @staticmethod
    def _deny(reason: str) -> dict:
        """Return ADK-native denial dict."""
        return {"error": f"DENIED: {reason}"}

    def _check_tool_success(self, tool_name: str, tool_response: Any) -> bool:
        if self._guard._success_check is not None:
            return self._guard._success_check(tool_name, tool_response)
        if tool_response is None:
            return True
        if isinstance(tool_response, dict):
            if tool_response.get("is_error"):
                return False
            if tool_response.get("error"):
                return False
        if isinstance(tool_response, str):
            if tool_response.startswith("Error:") or tool_response.startswith("fatal:"):
                return False
        return True

    async def _emit_audit_pre(self, envelope: Any, decision: Any, audit_action: AuditAction | None = None) -> None:
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
            )
        )

    async def _emit_error_audit(self, call_id: str | None, error: Exception) -> None:
        """Emit CALL_FAILED audit for tool errors. Used by on_tool_error_callback."""
        pending = self._pending.pop(call_id, None) if call_id else None
        if not pending:
            return
        envelope, span = pending
        try:
            await self._session.record_execution(envelope.tool_name, success=False)
            await self._guard.audit_sink.emit(
                AuditEvent(
                    action=AuditAction.CALL_FAILED,
                    run_id=envelope.run_id,
                    call_id=envelope.call_id,
                    call_index=envelope.call_index,
                    tool_name=envelope.tool_name,
                    tool_args=self._guard.redaction.redact_args(envelope.args),
                    side_effect=envelope.side_effect.value,
                    environment=envelope.environment,
                    principal=asdict(envelope.principal) if envelope.principal else None,
                    tool_success=False,
                    error=str(error),
                    session_attempt_count=await self._session.attempt_count(),
                    session_execution_count=await self._session.execution_count(),
                    mode=self._guard.mode,
                    policy_version=self._guard.policy_version,
                )
            )
            span.set_attribute("governance.tool_success", False)
            span.set_attribute("governance.error", str(error))
        finally:
            span.end()

    async def _handle_approval(self, envelope: Any, decision: Any, span: Any) -> dict | None:
        """Handle pending_approval decisions. Returns denial dict or None to proceed."""
        if self._guard._approval_backend is None:
            await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_DENIED)
            span.set_attribute("governance.action", "denied")
            span.end()
            return self._deny("Approval required but no approval backend configured")

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
            if self._guard._on_allow:
                try:
                    self._guard._on_allow(envelope)
                except Exception:
                    logger.exception("on_allow callback raised")
            span.set_attribute("governance.action", "approved")
            return None  # Proceed with execution

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
        span.end()
        return self._deny(f"Approval denied: {reason}")

    def as_plugin(
        self,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> Any:
        """Return a Plugin for Runner(plugins=[...]).

        The plugin applies governance to ALL tools across ALL agents
        managed by the runner. This is the recommended integration path.

        Args:
            on_postcondition_warn: Optional callback invoked when postconditions
                detect issues. Receives (original_result, findings) and is called
                for side effects. Overrides the constructor value if provided.

        Note:
            Plugins are NOT invoked in ADK's live/streaming mode.
            Use as_agent_callbacks() if live mode governance is needed.
        """
        from google.adk.plugins.base_plugin import BasePlugin

        adapter = self
        if on_postcondition_warn is not None:
            adapter._on_postcondition_warn = on_postcondition_warn

        class _EdictumPlugin(BasePlugin):
            def __init__(self):
                super().__init__(name="edictum")

            async def before_tool_callback(self, *, tool, tool_args, tool_context):
                call_id = getattr(tool_context, "function_call_id", None) or str(uuid.uuid4())
                # Store resolved call_id so after/error callbacks can find it
                try:
                    tool_context._edictum_call_id = call_id
                except AttributeError:
                    pass  # read-only context
                result = await adapter._pre(
                    tool_name=tool.name,
                    tool_input=tool_args,
                    call_id=call_id,
                    tool_context=tool_context,
                )
                return result  # None or dict

            async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
                call_id = getattr(tool_context, "_edictum_call_id", None) or getattr(
                    tool_context, "function_call_id", None
                )
                post_result = await adapter._post(call_id, result)
                if post_result.output_suppressed:
                    return {"error": "DENIED: output suppressed by postcondition"}
                if post_result.result is not result:
                    if isinstance(post_result.result, dict):
                        return post_result.result
                    return {"result": str(post_result.result)}
                return None  # keep original

            async def on_tool_error_callback(self, *, tool, tool_args, tool_context, error):
                call_id = getattr(tool_context, "_edictum_call_id", None) or getattr(
                    tool_context, "function_call_id", None
                )
                await adapter._emit_error_audit(call_id, error)
                return None  # re-raise the exception

        return _EdictumPlugin()

    def as_agent_callbacks(
        self,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> tuple[Callable, Callable, Callable]:
        """Return (before_tool_callback, after_tool_callback, error_tool_callback) for LlmAgent.

        Use this for per-agent scoping or when live/streaming mode
        governance is needed (plugins don't run in live mode).

        Args:
            on_postcondition_warn: Optional callback invoked when postconditions
                detect issues. Receives (original_result, findings) and is called
                for side effects.

        Returns:
            Tuple of (before_tool_callback, after_tool_callback, error_tool_callback).
            Pass the first two to ``LlmAgent(before_tool_callback=...,
            after_tool_callback=...)``. The third handles tool exceptions —
            wire it up separately if your runner supports error callbacks.
        """
        adapter = self
        if on_postcondition_warn is not None:
            adapter._on_postcondition_warn = on_postcondition_warn

        async def before_tool_callback(tool, args, tool_context):
            call_id = getattr(tool_context, "function_call_id", None) or str(uuid.uuid4())
            try:
                tool_context._edictum_call_id = call_id
            except AttributeError:
                pass  # read-only context
            result = await adapter._pre(
                tool_name=tool.name,
                tool_input=args,
                call_id=call_id,
                tool_context=tool_context,
            )
            return result  # None or dict

        async def after_tool_callback(tool, args, tool_context, tool_response):
            call_id = getattr(tool_context, "_edictum_call_id", None) or getattr(tool_context, "function_call_id", None)
            post_result = await adapter._post(call_id, tool_response)
            if post_result.output_suppressed:
                return {"error": "DENIED: output suppressed by postcondition"}
            if post_result.result is not tool_response:
                if isinstance(post_result.result, dict):
                    return post_result.result
                return {"result": str(post_result.result)}
            return None  # keep original

        async def error_tool_callback(tool, args, tool_context, error):
            call_id = getattr(tool_context, "_edictum_call_id", None) or getattr(tool_context, "function_call_id", None)
            await adapter._emit_error_audit(call_id, error)
            return None  # re-raise the exception

        return before_tool_callback, after_tool_callback, error_tool_callback

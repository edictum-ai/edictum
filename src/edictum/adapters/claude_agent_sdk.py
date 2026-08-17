"""Claude Agent SDK adapter — thin translation layer."""

from __future__ import annotations

import copy
import logging
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from typing import TYPE_CHECKING, Any

from edictum.approval import ApprovalStatus
from edictum.audit import AuditAction, AuditEvent, CompositeSink
from edictum.envelope import Principal, ToolCall, _validate_tool_name, create_envelope
from edictum.findings import Finding, build_findings
from edictum.pipeline import CheckPipeline, PreDecision
from edictum.session import Session, validate_session_id
from edictum.telemetry import _NoOpSpan
from edictum.workflow.state import build_workflow_snapshot

logger = logging.getLogger(__name__)
_MAX_WORKFLOW_APPROVAL_ROUNDS = 32
# Fixed reason code for D7 / O7: a silently-broken observe trial must be visible.
ADAPTER_INTERNAL_EXCEPTION_REASON = "adapter_internal_exception"
ADAPTER_POST_HOOK_EXCEPTION_REASON = "adapter_post_hook_exception"
ADAPTER_UNKNOWN_TOOL_NAME = "unknown_tool"
_EXECUTION_RECORD_STEPS = frozenset({"execs", "tool", "status"})
_MAX_GOVERNED_INPUT_DEPTH = 64
_PERMISSION_BOUNDARY_REASON = (
    "BLOCKED: Edictum rejected an unsafe or invalid SDK permission result; "
    "input and permission mutations are not supported after PreToolUse governance"
)
_INPUT_REPLACEMENT_REASON = "BLOCKED: Edictum rejected a tool input replacement after PreToolUse governance"
_INPUT_COMPARE_REASON = "BLOCKED: Edictum could not compare tool input against the governed snapshot"
_INVALID_TOOL_INPUT_REASON = "BLOCKED: Claude Agent SDK supplied invalid tool input"
_INVALID_TOOL_NAME_REASON = "BLOCKED: Claude Agent SDK supplied invalid tool name"
_MISSING_TOOL_USE_ID_REASON = "BLOCKED: Claude Agent SDK PreToolUse omitted tool_use_id"
_NO_GOVERNED_SNAPSHOT_REASON = "BLOCKED: Claude Agent SDK permission callback had no governed PreToolUse snapshot"


@dataclass
class _SdkHookMatcher:
    """Stand-in matcher when claude-agent-sdk is not installed.

    The host converts matchers via ``matcher.matcher`` / ``matcher.hooks``.
    """

    matcher: str | None = None
    hooks: list = field(default_factory=list)


@dataclass
class _PermissionAllow:
    behavior: str = "allow"
    updated_input: dict[str, Any] | None = None
    updated_permissions: list[Any] | None = None


@dataclass
class _PermissionDeny:
    behavior: str = "deny"
    message: str = ""
    interrupt: bool = False


@dataclass
class _HookRecovery:
    """Per-tool-call observe-exception stash. Do not share one adapter slot."""

    envelope: Any | None = None
    envelope_attempted: bool = False
    decision: PreDecision | None = None
    span: Any | None = None
    span_attempted: bool = False
    call_index_advanced: bool = False
    attempts_advanced: bool = False


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value)


def _hook_matcher(hooks: list) -> Any:
    try:
        from claude_agent_sdk.types import HookMatcher

        return HookMatcher(hooks=hooks)
    except ImportError:
        return _SdkHookMatcher(hooks=hooks)


def _permission_allow(*, updated_input: dict[str, Any] | None = None) -> Any:
    try:
        from claude_agent_sdk.types import PermissionResultAllow

        return PermissionResultAllow(updated_input=updated_input)
    except ImportError:
        return _PermissionAllow(updated_input=updated_input)


def _permission_deny(message: str, interrupt: bool = False) -> Any:
    try:
        from claude_agent_sdk.types import PermissionResultDeny

        return PermissionResultDeny(message=message, interrupt=interrupt)
    except ImportError:
        return _PermissionDeny(message=message, interrupt=interrupt)


def _governed_input_equals(left: Any, right: Any, depth: int = 0) -> bool:
    """Deep-compare the tool args that will execute against the governed snapshot."""
    if depth > _MAX_GOVERNED_INPUT_DEPTH:
        raise TypeError("BLOCKED: tool input exceeded compare depth")
    if left is right:
        return True
    if left is None or right is None:
        return False
    if type(left) is not type(right):
        return False
    if isinstance(left, (str, bytes, bool, int, float)):
        return left == right
    if isinstance(left, datetime):
        return left == right
    if isinstance(left, list):
        if len(left) != len(right):
            return False
        return all(_governed_input_equals(a, b, depth + 1) for a, b in zip(left, right, strict=True))
    if isinstance(left, dict):
        if type(left) is not dict or type(right) is not dict:
            raise TypeError("BLOCKED: governed input compare requires plain JSON-like values")
        if left.keys() != right.keys():
            return False
        return all(_governed_input_equals(left[k], right[k], depth + 1) for k in left)
    raise TypeError("BLOCKED: governed input compare requires plain JSON-like values")


if TYPE_CHECKING:
    from edictum import Edictum


class ClaudeAgentSDKAdapter:
    """Translate Edictum pipeline decisions into Claude SDK hook format.

    The adapter does NOT contain governance logic -- that lives in
    CheckPipeline. The adapter only:
    1. Creates envelopes from SDK input
    2. Manages pending state (envelope + span) between Pre/Post
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
        self._pending_decisions: dict[str, Any] = {}
        self._principal = principal
        self._principal_resolver = principal_resolver
        self._parent_session_id: str | None = None
        self._internal_exception_count = 0
        self._hook_recovery: dict[str, _HookRecovery] = {}
        self._execution_audit_completed: set[str] = set()
        self._execution_tool_success: dict[str, bool] = {}
        self._execution_recorded: set[str] = set()
        self._execution_record_steps: dict[str, set[str]] = {}
        self._pending_workflow_events: dict[str, list[dict]] = {}
        self._pending_execution_event: dict[str, AuditEvent] = {}
        self._sink_ack: dict[int, set[tuple[str, str]]] = {}

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
        ``ClaudeAgentOptions(hooks=...)``. Use ``to_sdk_hooks()`` for the
        host hook protocol matchers.

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

        async def pre_tool_use(tool_name: str, tool_input: dict, tool_use_id: str, **kwargs) -> dict[str, Any]:
            try:
                return await self._pre_tool_use(tool_name, tool_input, tool_use_id, **kwargs)
            finally:
                if tool_use_id not in self._pending:
                    self._hook_recovery.pop(tool_use_id, None)

        async def post_tool_use(tool_use_id: str, tool_response: Any = None, **kwargs) -> dict[str, Any]:
            pending_snapshot = self._pending.get(tool_use_id)
            try:
                return await self._post_tool_use(tool_use_id, tool_response=tool_response, **kwargs)
            except Exception:
                logger.exception("Claude raw post_tool_use raised")
                try:
                    await self._audit_post_hook_exception(pending_snapshot, tool_response)
                except Exception:
                    logger.exception("Claude post-hook exception audit failed")
                return {}
            finally:
                envelope_call_id = ""
                if pending_snapshot:
                    envelope_call_id = getattr(pending_snapshot[0], "call_id", "") or ""
                self._clear_call_state(envelope_call_id, tool_use_id)

        return {
            "pre_tool_use": pre_tool_use,
            "post_tool_use": post_tool_use,
        }

    def to_sdk_hooks(
        self,
        on_postcondition_warn: Callable[[Any, list[Finding]], Any] | None = None,
    ) -> dict[str, list[Any]]:
        """Return SDK-native hook matchers for ClaudeAgentOptions.hooks.

        Shape matches the host hook protocol: ``{event: [HookMatcher(hooks=[fn])]}``.
        Pass → ``{}`` (emit nothing). Block → ``permissionDecision: deny``.
        Never emit the SDK's ``ask`` or ``allow``.
        """
        warning_cb = on_postcondition_warn

        async def pre_tool_use(input: Any, tool_use_id: str | None, context: Any) -> dict[str, Any]:
            hook_event = ""
            if isinstance(input, dict):
                hook_event = str(input.get("hook_event_name") or "")
            else:
                hook_event = str(getattr(input, "hook_event_name", "") or "")
            if hook_event and hook_event != "PreToolUse":
                return {}

            tool_name = ""
            tool_input: Any = None
            input_tool_use_id = None
            if isinstance(input, dict):
                tool_name = input.get("tool_name") or ""
                tool_input = input.get("tool_input")
                input_tool_use_id = input.get("tool_use_id")
            else:
                tool_name = getattr(input, "tool_name", "") or ""
                tool_input = getattr(input, "tool_input", None)
                input_tool_use_id = getattr(input, "tool_use_id", None)

            call_id = tool_use_id or input_tool_use_id
            if not isinstance(call_id, str) or not call_id:
                return await self._block_pending("", tool_name, _MISSING_TOOL_USE_ID_REASON)
            try:
                if not isinstance(tool_input, dict):
                    return await self._block_pending(call_id, tool_name, _INVALID_TOOL_INPUT_REASON)
                if not isinstance(tool_name, str):
                    return await self._block_pending(call_id, tool_name, _INVALID_TOOL_NAME_REASON)
                try:
                    _validate_tool_name(tool_name)
                except ValueError:
                    return await self._block_pending(call_id, tool_name, _INVALID_TOOL_NAME_REASON)

                pending = self._pending.get(call_id)
                if pending is not None:
                    envelope, _span = pending
                    try:
                        matches = envelope.tool_name == tool_name and _governed_input_equals(envelope.args, tool_input)
                    except Exception:
                        return await self._block_pending(call_id, tool_name, _INPUT_COMPARE_REASON)
                    if not matches:
                        return await self._block_pending(call_id, tool_name, _INPUT_REPLACEMENT_REASON)
                    return {}

                result = await self._pre_tool_use(tool_name, tool_input, call_id)
                if result:
                    return result

                stored = self._pending.get(call_id)
                try:
                    still_matches = (
                        stored is not None
                        and stored[0].tool_name == tool_name
                        and _governed_input_equals(stored[0].args, tool_input)
                    )
                except Exception:
                    return await self._block_pending(call_id, tool_name, _INPUT_COMPARE_REASON)
                if not still_matches:
                    return await self._block_pending(call_id, tool_name, _INPUT_REPLACEMENT_REASON)
                return {}
            except Exception:
                logger.exception("Claude PreToolUse hook raised")
                try:
                    await self._on_internal_exception(tool_name)
                except Exception:
                    logger.exception("Claude internal-exception audit failed")
                recovery = self._hook_recovery.get(call_id)
                envelope_call_id = ""
                if recovery is not None and recovery.envelope is not None:
                    envelope_call_id = getattr(recovery.envelope, "call_id", "") or ""
                if envelope_call_id:
                    self._clear_sink_ack(envelope_call_id)
                if self._guard.mode == "observe":
                    try:
                        await self._ensure_observe_exception_pending(tool_name, tool_input, call_id)
                    except Exception:
                        logger.exception("Claude observe-exception pending seed failed")
                    return {}
                return self._deny(ADAPTER_INTERNAL_EXCEPTION_REASON)
            finally:
                self._hook_recovery.pop(call_id, None)

        async def post_tool_use(input: Any, tool_use_id: str | None, context: Any) -> dict[str, Any]:
            hook_event = ""
            tool_response: Any = None
            input_tool_use_id = None
            if isinstance(input, dict):
                hook_event = str(input.get("hook_event_name") or "")
                tool_response = input.get("tool_response")
                input_tool_use_id = input.get("tool_use_id")
            else:
                hook_event = str(getattr(input, "hook_event_name", "") or "")
                tool_response = getattr(input, "tool_response", None)
                input_tool_use_id = getattr(input, "tool_use_id", None)
            if hook_event and hook_event != "PostToolUse":
                return {}
            call_id = tool_use_id or input_tool_use_id
            if not call_id:
                return {}
            pending_snapshot = self._pending.get(call_id)
            try:
                return await self._post_tool_use(
                    tool_use_id=call_id, tool_response=tool_response, on_postcondition_warn=warning_cb
                )
            except Exception:
                logger.exception("Claude PostToolUse hook raised; keeping original result")
                try:
                    await self._audit_post_hook_exception(pending_snapshot, tool_response)
                except Exception:
                    logger.exception("Claude post-hook exception audit failed")
                return {}

        async def post_tool_use_failure(input: Any, tool_use_id: str | None, context: Any) -> dict[str, Any]:
            hook_event = ""
            error = None
            input_tool_use_id = None
            if isinstance(input, dict):
                hook_event = str(input.get("hook_event_name") or "")
                error = input.get("error")
                input_tool_use_id = input.get("tool_use_id")
            else:
                hook_event = str(getattr(input, "hook_event_name", "") or "")
                error = getattr(input, "error", None)
                input_tool_use_id = getattr(input, "tool_use_id", None)
            if hook_event and hook_event != "PostToolUseFailure":
                return {}
            call_id = tool_use_id or input_tool_use_id
            if not call_id:
                return {}
            failure_response = {"is_error": True, "error": error}
            pending_snapshot = self._pending.get(call_id)
            try:
                result = await self._post_tool_use(
                    tool_use_id=call_id, tool_response=failure_response, on_postcondition_warn=warning_cb
                )
            except Exception:
                logger.exception("Claude PostToolUseFailure hook raised")
                try:
                    await self._audit_post_hook_exception(pending_snapshot, failure_response)
                except Exception:
                    logger.exception("Claude post-hook exception audit failed")
                return {}
            if not result:
                return {}
            specific = result.get("hookSpecificOutput")
            if isinstance(specific, dict):
                specific = dict(specific)
                specific["hookEventName"] = "PostToolUseFailure"
                return {"hookSpecificOutput": specific}
            return result

        hooks = {
            "PreToolUse": [_hook_matcher([pre_tool_use])],
            "PostToolUse": [_hook_matcher([post_tool_use])],
            "PostToolUseFailure": [_hook_matcher([post_tool_use_failure])],
        }
        return hooks

    def wrap_can_use_tool(self, callback: Callable) -> Callable:
        """Wrap an SDK permission callback so it cannot mutate args after PreToolUse."""

        async def wrapped(tool_name: str, tool_input: dict[str, Any], context: Any) -> Any:
            call_id = getattr(context, "tool_use_id", None)
            if isinstance(context, dict):
                call_id = context.get("tool_use_id", call_id)
            if not isinstance(call_id, str) or not call_id:
                call_id = ""

            async def deny(reason: str, interrupt: bool = False) -> Any:
                await self._block_pending(call_id, tool_name, reason)
                return _permission_deny(reason, interrupt=interrupt)

            try:
                pending = self._pending_for_permission(tool_name, tool_input, context)
                if isinstance(pending, tuple):
                    call_id = pending[2]
                if pending == "ambiguous":
                    self._clear_matching_pending(tool_name, tool_input)
                    return await deny(_INPUT_REPLACEMENT_REASON)
                if pending == "mismatch":
                    return await deny(_INPUT_REPLACEMENT_REASON)
                if pending == "compare_failed":
                    return await deny(_INPUT_COMPARE_REASON)
                if pending is None:
                    return await deny(_NO_GOVERNED_SNAPSHOT_REASON)

                isolated = copy.deepcopy(tool_input) if isinstance(tool_input, dict) else tool_input
                result = await callback(tool_name, isolated, context)

                if isinstance(pending, tuple):
                    envelope = pending[0]
                    try:
                        if envelope.tool_name != tool_name or not _governed_input_equals(envelope.args, tool_input):
                            return await deny(_PERMISSION_BOUNDARY_REASON)
                    except Exception:
                        return await deny(_INPUT_COMPARE_REASON)

                if result is None:
                    return await deny(_PERMISSION_BOUNDARY_REASON)

                behavior, updated_input, updated_permissions, message, interrupt = self._permission_fields(result)
                if behavior == "allow":
                    if updated_input is not None or updated_permissions is not None:
                        return await deny(_PERMISSION_BOUNDARY_REASON)
                    pinned = None
                    if isinstance(pending, tuple):
                        pinned = copy.deepcopy(pending[0].args)
                    return _permission_allow(updated_input=pinned)
                if behavior == "deny":
                    if not isinstance(message, str):
                        return await deny(_PERMISSION_BOUNDARY_REASON)
                    if interrupt is not None and not isinstance(interrupt, bool):
                        return await deny(_PERMISSION_BOUNDARY_REASON)
                    if _has_control_chars(message):
                        return await deny(_PERMISSION_BOUNDARY_REASON)
                    return await deny(message, interrupt=bool(interrupt))
                return await deny(_PERMISSION_BOUNDARY_REASON)
            except Exception:
                logger.exception("Claude can_use_tool wrapper raised")
                return await deny(_PERMISSION_BOUNDARY_REASON)

        return wrapped

    def _pending_for_permission(self, tool_name: str, tool_input: Any, context: Any) -> Any:
        tool_use_id = getattr(context, "tool_use_id", None)
        if isinstance(context, dict):
            tool_use_id = context.get("tool_use_id", tool_use_id)
        if not isinstance(tool_use_id, str) or not tool_use_id:
            tool_use_id = None
        if tool_use_id and tool_use_id in self._pending:
            envelope, span = self._pending[tool_use_id]
            try:
                if envelope.tool_name == tool_name and _governed_input_equals(envelope.args, tool_input):
                    return (envelope, span, tool_use_id)
                return "mismatch"
            except Exception:
                return "compare_failed"

        same_name: list[tuple[str, Any, Any]] = []
        for key, (envelope, span) in self._pending.items():
            if envelope.tool_name == tool_name:
                same_name.append((key, envelope, span))
        if not same_name:
            return None
        matches: list[tuple[str, Any, Any]] = []
        for key, envelope, span in same_name:
            try:
                if _governed_input_equals(envelope.args, tool_input):
                    matches.append((key, envelope, span))
            except Exception:
                return "compare_failed"
        if len(matches) == 1:
            key, envelope, span = matches[0]
            return (envelope, span, key)
        if matches:
            return "ambiguous"
        return "mismatch"

    @staticmethod
    def _permission_fields(result: Any) -> tuple[Any, Any, Any, Any, Any]:
        if isinstance(result, dict):
            return (
                result.get("behavior"),
                result.get("updated_input", result.get("updatedInput")),
                result.get("updated_permissions", result.get("updatedPermissions")),
                result.get("message", ""),
                result.get("interrupt", False),
            )
        return (
            getattr(result, "behavior", None),
            getattr(result, "updated_input", None),
            getattr(result, "updated_permissions", None),
            getattr(result, "message", ""),
            getattr(result, "interrupt", False),
        )

    async def _block_pending(self, call_id: str, tool_name: str, reason: str) -> dict[str, Any]:
        """Emit the adapter blocked-call audit, then clear pending and return a host block."""
        pending = self._pending.get(call_id)
        envelope = pending[0] if pending is not None else None
        try:
            await self._audit_adapter_block(tool_name, reason, envelope)
        except Exception:
            logger.exception("Claude host-block audit failed")
        self._clear_pending(call_id)
        return self._deny(reason)

    def _clear_matching_pending(self, tool_name: str, tool_input: Any) -> None:
        keys: list[str] = []
        for key, (envelope, _span) in list(self._pending.items()):
            try:
                if envelope.tool_name == tool_name and _governed_input_equals(envelope.args, tool_input):
                    keys.append(key)
            except Exception:
                continue
        for key in keys:
            self._clear_pending(key)

    def _clear_pending(self, call_id: str) -> None:
        """Remove pending state and end the saved span for a blocked call."""
        pending = self._pending.pop(call_id, None)
        self._pending_decisions.pop(call_id, None)
        if pending is None:
            return
        envelope, span = pending
        self._clear_sink_ack(getattr(envelope, "call_id", "") or call_id)
        self._hook_recovery.pop(call_id, None)
        try:
            span.end()
        except Exception:
            logger.exception("Claude pending span end failed")

    def _fanout_sinks(self) -> list[Any]:
        return self._flatten_sinks(self._guard.audit_sink)

    @staticmethod
    def _flatten_sinks(sink: Any) -> list[Any]:
        if not isinstance(sink, CompositeSink):
            return [sink]
        children = sink.sinks
        if not children:
            return [sink]
        leaves: list[Any] = []
        for child in children:
            leaves.extend(ClaudeAgentSDKAdapter._flatten_sinks(child))
        return leaves

    @staticmethod
    def _ack_identity(event: AuditEvent) -> tuple[str, str, str] | None:
        call_id = getattr(event, "call_id", "")
        action = getattr(event, "action", None)
        if not call_id or action is None:
            return None
        action_key = action.value if isinstance(action, AuditAction) else str(action)
        extra = ""
        workflow = getattr(event, "workflow", None)
        if isinstance(workflow, dict) and action_key not in (
            AuditAction.CALL_EXECUTED.value,
            AuditAction.CALL_FAILED.value,
        ):
            completed = workflow.get("completed_stages") or ()
            extra = (
                f"{workflow.get('name', '')}:"
                f"{workflow.get('active_stage', '')}:"
                f"{tuple(completed)}:"
                f"{workflow.get('stage_id', '')}:"
                f"{workflow.get('to_stage_id', '')}"
            )
        return (call_id, action_key, extra)

    def _ack_sink(self, sink: Any, event: AuditEvent) -> None:
        identity = self._ack_identity(event)
        if identity is None:
            return
        self._sink_ack.setdefault(id(sink), set()).add(identity)

    def _sink_acked(self, sink: Any, event: AuditEvent) -> bool:
        identity = self._ack_identity(event)
        if identity is None:
            return False
        return identity in self._sink_ack.get(id(sink), set())

    def _clear_call_state(self, envelope_call_id: str = "", tool_use_id: str = "") -> None:
        if envelope_call_id:
            self._execution_audit_completed.discard(envelope_call_id)
            self._execution_tool_success.pop(envelope_call_id, None)
            self._execution_recorded.discard(envelope_call_id)
            self._execution_record_steps.pop(envelope_call_id, None)
            self._pending_workflow_events.pop(envelope_call_id, None)
            self._pending_execution_event.pop(envelope_call_id, None)
            self._clear_sink_ack(envelope_call_id)
        if tool_use_id:
            self._hook_recovery.pop(tool_use_id, None)

    def _clear_sink_ack(self, call_id: str) -> None:
        if not call_id:
            return
        for sink_id, keys in list(self._sink_ack.items()):
            remaining = {key for key in keys if key[0] != call_id}
            if remaining:
                self._sink_ack[sink_id] = remaining
            else:
                del self._sink_ack[sink_id]

    async def _emit_per_sink(self, event: AuditEvent) -> None:
        """Fan out one audit, skipping sinks that already accepted this call+action."""
        errors: list[Exception] = []
        for sink in self._fanout_sinks():
            if self._sink_acked(sink, event):
                continue
            try:
                await sink.emit(event)
            except Exception as exc:
                errors.append(exc)
                continue
            self._ack_sink(sink, event)
        if errors:
            raise ExceptionGroup("Claude audit fan-out: one or more sinks failed", errors)

    async def _record_session_execution(self, call_id: str, tool_name: str, success: bool) -> None:
        """Apply remaining session execution counters without replaying completed ones."""
        _validate_tool_name(tool_name)
        completed = self._execution_record_steps.setdefault(call_id, set())
        if "execs" not in completed:
            await self._session._backend.increment(self._session._key("execs"))
            completed.add("execs")
        if "tool" not in completed:
            await self._session._backend.increment(self._session._key(f"tool:{tool_name}"))
            completed.add("tool")
        if "status" not in completed:
            if success:
                await self._session._backend.delete(self._session._key("consec_fail"))
            else:
                await self._session._backend.increment(self._session._key("consec_fail"))
            completed.add("status")
        if _EXECUTION_RECORD_STEPS <= completed:
            self._execution_recorded.add(call_id)

    async def _recover_workflow_events(self, envelope: Any) -> None:
        call_id = getattr(envelope, "call_id", "")
        records = self._pending_workflow_events.pop(call_id, None)
        if not records:
            return
        await self._emit_workflow_events(envelope, records)

    async def _audit_post_hook_exception(self, pending: Any, tool_response: Any) -> None:
        """Emit adapter-sourced executed/failed after a post-hook raise."""
        envelope = pending[0] if isinstance(pending, tuple) and pending else None
        try:
            if envelope is not None and envelope.call_id in self._execution_audit_completed:
                self._execution_audit_completed.discard(envelope.call_id)
                self._execution_tool_success.pop(envelope.call_id, None)
                await self._recover_workflow_events(envelope)
                return
            stashed = self._pending_execution_event.get(envelope.call_id) if envelope is not None else None
            if stashed is not None:
                await self._emit_per_sink(stashed)
                await self._recover_workflow_events(envelope)
                return
            tool_success = False
            if envelope is not None and envelope.call_id in self._execution_tool_success:
                tool_success = self._execution_tool_success.pop(envelope.call_id)
            elif envelope is not None:
                try:
                    tool_success = self._check_tool_success(envelope.tool_name, tool_response)
                except Exception:
                    tool_success = False
            action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
            reason = ADAPTER_POST_HOOK_EXCEPTION_REASON
            if envelope is not None and envelope.call_id not in self._execution_recorded:
                try:
                    await self._record_session_execution(envelope.call_id, envelope.tool_name, tool_success)
                except Exception:
                    logger.exception("Claude recovery record_execution failed")
            if envelope is not None:
                await self._emit_per_sink(
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
                        reason=reason,
                        decision_source="adapter",
                        decision_name=reason,
                        tool_success=tool_success,
                        mode=self._guard.mode,
                        policy_version=self._guard.policy_version,
                        policy_error=True,
                    )
                )
                await self._recover_workflow_events(envelope)
                return
            await self._guard.audit_sink.emit(
                AuditEvent(
                    action=action,
                    session_id=self._session_id,
                    tool_name=ADAPTER_UNKNOWN_TOOL_NAME,
                    reason=reason,
                    decision_source="adapter",
                    decision_name=reason,
                    tool_success=tool_success,
                    mode=self._guard.mode,
                    policy_version=self._guard.policy_version,
                    policy_error=True,
                )
            )
        finally:
            if envelope is not None:
                self._clear_call_state(envelope.call_id)

    async def _audit_adapter_block(self, tool_name: str, reason: str, envelope: Any | None = None) -> None:
        """Emit an adapter-sourced CALL_DENIED, keeping pending identity when present."""
        if envelope is not None:
            await self._guard.audit_sink.emit(
                AuditEvent(
                    action=AuditAction.CALL_DENIED,
                    run_id=envelope.run_id,
                    call_id=envelope.call_id,
                    call_index=envelope.call_index,
                    session_id=self._session_id,
                    parent_session_id=self._audit_parent_session_id(),
                    tool_name=envelope.tool_name or self._safe_tool_name(tool_name),
                    tool_args=self._guard.redaction.redact_args(envelope.args),
                    side_effect=envelope.side_effect.value,
                    environment=envelope.environment,
                    principal=asdict(envelope.principal) if envelope.principal else None,
                    reason=reason,
                    decision_source="adapter",
                    decision_name=reason,
                    mode=self._guard.mode,
                    policy_version=self._guard.policy_version,
                )
            )
            return
        await self._guard.audit_sink.emit(
            AuditEvent(
                action=AuditAction.CALL_DENIED,
                session_id=self._session_id,
                tool_name=self._safe_tool_name(tool_name),
                reason=reason,
                decision_source="adapter",
                decision_name=reason,
                mode=self._guard.mode,
                policy_version=self._guard.policy_version,
            )
        )

    @staticmethod
    def _safe_tool_name(name: Any) -> str:
        if not isinstance(name, str) or not name:
            return ADAPTER_UNKNOWN_TOOL_NAME
        try:
            _validate_tool_name(name)
        except ValueError:
            return ADAPTER_UNKNOWN_TOOL_NAME
        return name

    async def _on_internal_exception(self, tool_name: str) -> None:
        """Emit the D7 loud audit + counter/span for a hook-path exception."""
        self._internal_exception_count += 1
        reason = ADAPTER_INTERNAL_EXCEPTION_REASON
        mode = self._guard.mode
        action = AuditAction.CALL_WOULD_DENY if mode == "observe" else AuditAction.CALL_DENIED
        safe_name = self._safe_tool_name(tool_name)
        self._guard.telemetry.record_adapter_exception(safe_name, mode)
        await self._guard.audit_sink.emit(
            AuditEvent(
                action=action,
                session_id=self._session_id,
                tool_name=safe_name,
                reason=reason,
                decision_source="adapter",
                decision_name=reason,
                mode=mode,
                policy_version=self._guard.policy_version,
                policy_error=True,
            )
        )

    async def _ensure_observe_exception_pending(
        self,
        tool_name: str,
        tool_input: Any,
        tool_use_id: str,
    ) -> None:
        """Keep enough pending state so post-hook can record the allowed execution."""
        if tool_use_id in self._pending and tool_use_id in self._pending_decisions:
            return
        recovery = self._hook_recovery.get(tool_use_id)
        envelope = recovery.envelope if recovery is not None else None
        if envelope is None:
            safe_name = self._safe_tool_name(tool_name)
            args = tool_input if isinstance(tool_input, dict) else {}
            call_index_advanced = bool(recovery and recovery.call_index_advanced)
            call_index = self._call_index - 1 if call_index_advanced else self._call_index
            if recovery is not None and recovery.envelope_attempted:
                envelope = ToolCall(
                    tool_name=safe_name,
                    args=args,
                    run_id=self._session_id,
                    call_index=call_index,
                    tool_use_id=tool_use_id,
                    environment=self._guard.environment,
                    principal=self._principal,
                )
            else:
                envelope = create_envelope(
                    tool_name=safe_name,
                    tool_input=args,
                    run_id=self._session_id,
                    call_index=call_index,
                    tool_use_id=tool_use_id,
                    environment=self._guard.environment,
                    registry=self._guard.tool_registry,
                    principal=self._principal,
                )
        if recovery is not None and recovery.span is not None:
            span = recovery.span
        elif recovery is not None and recovery.span_attempted:
            span = _NoOpSpan()
        else:
            span = self._guard.telemetry.start_tool_span(envelope)
        if recovery is not None and recovery.decision is not None:
            decision = recovery.decision
        else:
            decision = PreDecision(
                action="allow",
                reason=ADAPTER_INTERNAL_EXCEPTION_REASON,
                decision_source="adapter",
                decision_name=ADAPTER_INTERNAL_EXCEPTION_REASON,
                policy_error=True,
            )
        self._pending[tool_use_id] = (envelope, span)
        self._pending_decisions[tool_use_id] = decision
        if recovery is None or not recovery.call_index_advanced:
            self._call_index += 1
            if recovery is not None:
                recovery.call_index_advanced = True
        if recovery is None or not recovery.attempts_advanced:
            if recovery is not None:
                recovery.attempts_advanced = True
            await self._session.increment_attempts()

    async def _pre_tool_use(self, tool_name: str, tool_input: dict, tool_use_id: str, **kwargs) -> dict[str, Any]:
        recovery = _HookRecovery()
        self._hook_recovery[tool_use_id] = recovery

        # Create envelope
        recovery.envelope_attempted = True
        envelope = create_envelope(
            tool_name=tool_name,
            tool_input=tool_input,
            run_id=self._session_id,
            call_index=self._call_index,
            tool_use_id=tool_use_id,
            environment=self._guard.environment,
            registry=self._guard.tool_registry,
            principal=self._resolve_principal(tool_name, tool_input),
        )
        recovery.envelope = envelope
        self._call_index += 1
        recovery.call_index_advanced = True

        # Increment attempts BEFORE governance
        recovery.attempts_advanced = True
        await self._session.increment_attempts()

        # Start OTel span
        recovery.span_attempted = True
        span = self._guard.telemetry.start_tool_span(envelope)
        recovery.span = span

        try:
            # Run pipeline
            decision = await self._pipeline.pre_execute(envelope, self._session)
            recovery.decision = decision
            await self._emit_workflow_events(envelope, decision.workflow_events)

            # Handle observe mode: convert block to allow with warning
            if self._guard.mode == "observe" and decision.action == "block":
                await self._emit_audit_pre(envelope, decision, audit_action=AuditAction.CALL_WOULD_DENY)
                span.set_attribute("governance.action", "would_deny")
                span.set_attribute("governance.would_deny_reason", decision.reason)
                self._pending[tool_use_id] = (envelope, span)
                self._pending_decisions[tool_use_id] = decision
                return {}  # allow through

            if decision.action == "pending_approval":
                blocked_result, decision = await self._resolve_pending_approval(envelope, decision, span)
                if blocked_result is not None:
                    span.end()
                    self._pending.pop(tool_use_id, None)
                    self._pending_decisions.pop(tool_use_id, None)
                    self._clear_sink_ack(envelope.call_id)
                    return blocked_result

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
                self._pending.pop(tool_use_id, None)
                self._pending_decisions.pop(tool_use_id, None)
                self._clear_sink_ack(envelope.call_id)
                return self._deny(decision.reason or "")

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
            self._pending[tool_use_id] = (envelope, span)
            self._pending_decisions[tool_use_id] = decision
            return {}

        except Exception:
            if tool_use_id not in self._pending:
                span.end()
            raise

    async def _post_tool_use(
        self,
        tool_use_id: str,
        tool_response: Any = None,
        **kwargs,
    ) -> dict[str, Any]:
        pending = self._pending.pop(tool_use_id, None)
        if not pending:
            return {}

        decision = self._pending_decisions.pop(tool_use_id, None)
        if decision is None:
            _, span = pending
            span.end()
            return {}

        envelope, span = pending

        try:
            # Derive tool_success from SDK response
            tool_success = self._check_tool_success(envelope.tool_name, tool_response)
            self._execution_tool_success[envelope.call_id] = tool_success

            # Run pipeline
            post_decision = await self._pipeline.post_execute(envelope, tool_response, tool_success)

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
            self._pending_workflow_events[envelope.call_id] = list(workflow_events)
            workflow = decision.workflow
            if decision.workflow_involved and self._guard._workflow_runtime is not None:
                workflow_state = await self._guard._workflow_runtime.state(self._session)
                workflow = build_workflow_snapshot(self._guard._workflow_runtime.definition, workflow_state)

            # Record in session. Track completed counter steps so recovery
            # can finish remaining writes without replaying successful ones.
            await self._record_session_execution(envelope.call_id, envelope.tool_name, tool_success)

            # Emit audit. Mark complete only after emit returns so a sink
            # that rejects the primary event can still receive fallback.
            action = AuditAction.CALL_EXECUTED if tool_success else AuditAction.CALL_FAILED
            event = AuditEvent(
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
            self._pending_execution_event[envelope.call_id] = event
            await self._emit_per_sink(event)
            self._execution_audit_completed.add(envelope.call_id)
            await self._emit_workflow_events(envelope, workflow_events)
            self._pending_workflow_events.pop(envelope.call_id, None)

            span.set_attribute("governance.tool_success", tool_success)
            span.set_attribute("governance.postconditions_passed", post_decision.postconditions_passed)

            if tool_success:
                self._guard.telemetry.set_span_ok(span)
            else:
                self._guard.telemetry.set_span_error(span, "tool execution failed")
        finally:
            span.end()

        # Build violations and call callback with effective response.
        effective_response = (
            post_decision.redacted_response if post_decision.redacted_response is not None else tool_response
        )
        violations = build_findings(post_decision)
        on_warn = kwargs.get("on_postcondition_warn")
        if on_warn is None:
            on_warn = getattr(self, "_on_postcondition_warn", None)
        if not post_decision.postconditions_passed and violations and on_warn:
            try:
                on_warn(effective_response, violations)
            except Exception:
                logger.exception("on_postcondition_warn callback raised")

        # Return warnings as additionalContext
        self._clear_call_state(envelope.call_id, tool_use_id)
        if post_decision.warnings:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": "\n".join(post_decision.warnings),
                }
            }
        return {}

    async def _emit_audit_pre(self, envelope, decision, audit_action=None):
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
            await self._emit_per_sink(
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
    ) -> tuple[dict | None, Any]:
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

    async def _handle_approval(self, envelope: Any, decision: Any, span: Any) -> dict | None:
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
        return True

    def _deny(self, reason: str) -> dict[str, Any]:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }

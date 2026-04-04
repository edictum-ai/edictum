"""Server-backed audit sink with batching."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from copy import deepcopy
from typing import Any

from edictum.server.client import EdictumServerClient

logger = logging.getLogger(__name__)

_ACTION_MAP = {
    "call_denied": "call_blocked",
    "call_would_deny": "call_would_block",
    "call_approval_requested": "call_asked",
    "call_approval_denied": "call_approval_blocked",
}
_WORKFLOW_PROGRESS_ACTIONS = frozenset(
    {
        "workflow_stage_advanced",
        "workflow_completed",
        "workflow_state_updated",
    }
)


class ServerAuditSink:
    """Audit sink that sends events to the edictum-server.

    Batches events and flushes periodically or when batch is full.
    """

    MAX_BUFFER_SIZE = 10_000

    def __init__(
        self,
        client: EdictumServerClient,
        *,
        batch_size: int = 50,
        flush_interval: float = 5.0,
        max_buffer_size: int = MAX_BUFFER_SIZE,
    ) -> None:
        self._client = client
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_buffer_size = max_buffer_size
        self._buffer: list[dict[str, Any]] = []
        self._flush_task: asyncio.Task | None = None
        self._flush_task_loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self._workflow_snapshot_provider: Callable[[Any], Awaitable[dict[str, Any] | None]] | None = None

    async def emit(self, event: Any) -> None:
        """Convert an AuditEvent to server format and add to batch buffer."""
        payload = await self._prepare_payload(event)
        with self._lock:
            self._buffer.append(payload)
            needs_flush = len(self._buffer) >= self._batch_size

        if needs_flush:
            await self._flush()
        else:
            try:
                current_loop = asyncio.get_running_loop()
            except RuntimeError:
                return
            # TOCTOU: two threads can both see task_active=False and create
            # tasks; the second overwrites _flush_task, orphaning the first.
            # Benign: the orphaned task does one harmless flush then is cancelled
            # when the worker's asyncio.run() exits. close() always calls flush()
            # regardless, so no data loss.
            task_active = (
                self._flush_task is not None and not self._flush_task.done() and self._flush_task_loop is current_loop
            )
            if not task_active:
                self._flush_task = asyncio.create_task(self._auto_flush())
                self._flush_task_loop = current_loop

    async def _prepare_payload(self, event: Any) -> dict[str, Any]:
        workflow = await self._resolve_workflow_snapshot(event)
        return self._map_event(event, workflow=workflow)

    async def _resolve_workflow_snapshot(self, event: Any) -> dict[str, Any] | None:
        workflow = getattr(event, "workflow", None)
        if not self._needs_workflow_snapshot(event, workflow):
            if isinstance(workflow, dict):
                return deepcopy(workflow)
            return None

        provider = self._workflow_snapshot_provider
        if provider is None:
            if isinstance(workflow, dict):
                return deepcopy(workflow)
            return None

        try:
            snapshot = await provider(event)
        except Exception:
            logger.warning("Failed to load workflow snapshot for audit event", exc_info=True)
            if isinstance(workflow, dict):
                return deepcopy(workflow)
            return None

        if not isinstance(snapshot, dict):
            if isinstance(workflow, dict):
                return deepcopy(workflow)
            return None

        merged = deepcopy(snapshot)
        if isinstance(workflow, dict):
            merged.update(deepcopy(workflow))
        return merged

    def _needs_workflow_snapshot(self, event: Any, workflow: Any) -> bool:
        action = getattr(getattr(event, "action", None), "value", getattr(event, "action", None))
        return (
            isinstance(action, str) and action in _WORKFLOW_PROGRESS_ACTIONS and not self._has_full_workflow(workflow)
        )

    def _has_full_workflow(self, workflow: Any) -> bool:
        if not isinstance(workflow, dict):
            return False
        required_keys = {"name", "active_stage", "completed_stages", "pending_approval"}
        return required_keys.issubset(workflow)

    def _map_event(self, event: Any, *, workflow: dict[str, Any] | None = None) -> dict[str, Any]:
        """Map an AuditEvent to the server EventPayload format."""
        if workflow is None:
            event_workflow = getattr(event, "workflow", None)
            if isinstance(event_workflow, dict):
                workflow = event_workflow
        payload: dict[str, Any] = {
            "schema_version": getattr(event, "schema_version", "0.3.0"),
            "call_id": event.call_id,
            "agent_id": self._client.agent_id,
            "tool_name": event.tool_name,
            "tool_args": deepcopy(event.tool_args),
            "side_effect": event.side_effect,
            "environment": getattr(event, "environment", None) or self._client.env,
            "principal": deepcopy(event.principal),
            "action": self._map_action(getattr(event.action, "value", event.action)),
            "decision_source": event.decision_source,
            "decision_name": event.decision_name,
            "reason": event.reason,
            "hooks_evaluated": deepcopy(getattr(event, "hooks_evaluated", [])),
            "rules_evaluated": deepcopy(getattr(event, "contracts_evaluated", [])),
            "mode": event.mode,
            "policy_version": event.policy_version,
            "timestamp": event.timestamp.isoformat(),
            "run_id": getattr(event, "run_id", ""),
            "call_index": getattr(event, "call_index", 0),
            "parent_call_id": getattr(event, "parent_call_id", None),
            "tool_success": getattr(event, "tool_success", None),
            "postconditions_passed": getattr(event, "postconditions_passed", None),
            "duration_ms": getattr(event, "duration_ms", 0),
            "error": getattr(event, "error", None),
            "result_summary": getattr(event, "result_summary", None),
            "session_attempt_count": getattr(event, "session_attempt_count", 0),
            "session_execution_count": getattr(event, "session_execution_count", 0),
            "policy_error": getattr(event, "policy_error", False),
        }
        session_id = getattr(event, "session_id", None)
        if session_id is not None:
            payload["session_id"] = session_id
        parent_session_id = getattr(event, "parent_session_id", None)
        if parent_session_id is not None:
            payload["parent_session_id"] = parent_session_id
        if isinstance(workflow, dict):
            payload["workflow"] = deepcopy(workflow)
        return payload

    def _map_action(self, action: Any) -> str:
        if not isinstance(action, str):
            return str(action)
        return _ACTION_MAP.get(action, action)

    async def flush(self) -> None:
        """Flush all buffered events to the server."""
        await self._flush()

    async def _flush(self) -> None:
        """Thread-safe flush: grab buffer under lock, send outside lock."""
        from edictum.server.client import EdictumServerError

        with self._lock:
            if not self._buffer:
                return
            events = list(self._buffer)
            self._buffer.clear()
        try:
            await self._client.post("/v1/events", {"events": events})
        except Exception as exc:
            # Non-retryable client errors (4xx except 429): raise immediately.
            # Auth errors (401/403) will never succeed on retry — surfacing them
            # prevents silent credential failure and infinite buffer growth.
            if isinstance(exc, EdictumServerError) and 400 <= exc.status_code < 500 and exc.status_code != 429:
                logger.error(
                    "Audit flush failed with non-retryable error (HTTP %d): %s",
                    exc.status_code,
                    exc.detail,
                )
                raise
            logger.warning("Failed to flush %d audit events, keeping in buffer for retry", len(events))
            self._restore_events(events)
        except BaseException:
            # CancelledError, KeyboardInterrupt, SystemExit — preserve events, re-raise
            self._restore_events(events)
            raise

    def _restore_events(self, events: list[dict[str, Any]]) -> None:
        """Re-add events to the front of the buffer after a failed flush.

        Concurrent flush failures may reorder events; the server uses
        event timestamps for ordering, not insertion order.
        """
        with self._lock:
            self._buffer = events + self._buffer
            if len(self._buffer) > self._max_buffer_size:
                dropped = len(self._buffer) - self._max_buffer_size
                self._buffer = self._buffer[dropped:]
                logger.warning("Buffer exceeded %d, dropped %d oldest", self._max_buffer_size, dropped)

    async def _auto_flush(self) -> None:
        """Background task: flush after flush_interval seconds."""
        await asyncio.sleep(self._flush_interval)
        await self.flush()

    async def close(self) -> None:
        """Flush remaining events and cancel the background flush task."""
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        if self._flush_task is not None and not self._flush_task.done() and self._flush_task_loop is current_loop:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self.flush()

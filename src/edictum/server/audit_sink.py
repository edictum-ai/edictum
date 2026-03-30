"""Server-backed audit sink with batching."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from edictum.audit import AuditAction
from edictum.server.client import EdictumServerClient

logger = logging.getLogger(__name__)

_CANONICAL_ACTIONS: dict[AuditAction, str] = {
    AuditAction.CALL_DENIED: "call_blocked",
    AuditAction.CALL_WOULD_DENY: "call_would_block",
    AuditAction.CALL_APPROVAL_REQUESTED: "call_asked",
    AuditAction.CALL_APPROVAL_DENIED: "call_approval_blocked",
}
_RULES_EVALUATED_KEY = "rules_evaluated"


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

    async def emit(self, event: Any) -> None:
        """Convert an AuditEvent to server format and add to batch buffer."""
        payload = self._map_event(event)
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

    def _map_event(self, event: Any) -> dict[str, Any]:
        """Map an AuditEvent to the canonical API event format."""
        action = _CANONICAL_ACTIONS.get(event.action, event.action.value)
        return {
            "schema_version": event.schema_version,
            "call_id": event.call_id,
            "agent_id": self._client.agent_id,
            "tool_name": event.tool_name,
            "tool_args": event.tool_args,
            "side_effect": event.side_effect,
            "environment": getattr(event, "environment", None) or self._client.env,
            "principal": event.principal,
            "action": action,
            "decision_source": event.decision_source,
            "decision_name": event.decision_name,
            "reason": event.reason,
            "hooks_evaluated": event.hooks_evaluated,
            _RULES_EVALUATED_KEY: event.contracts_evaluated,
            "mode": event.mode,
            "timestamp": event.timestamp.isoformat(),
            "run_id": event.run_id,
            "call_index": event.call_index,
            "parent_call_id": event.parent_call_id,
            "tool_success": event.tool_success,
            "postconditions_passed": event.postconditions_passed,
            "duration_ms": event.duration_ms,
            "error": event.error,
            "result_summary": event.result_summary,
            "session_attempt_count": event.session_attempt_count,
            "session_execution_count": event.session_execution_count,
            "policy_version": event.policy_version,
            "policy_error": event.policy_error,
        }

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

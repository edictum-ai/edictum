"""Server-backed audit sink with batching."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from edictum.server.client import EdictumServerClient

logger = logging.getLogger(__name__)


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
        self._lock = asyncio.Lock()

    async def emit(self, event: Any) -> None:
        """Convert an AuditEvent to server format and add to batch buffer."""
        payload = self._map_event(event)
        async with self._lock:
            self._buffer.append(payload)
            if len(self._buffer) >= self._batch_size:
                await self._flush_locked()
            elif self._flush_task is None or self._flush_task.done():
                self._flush_task = asyncio.create_task(self._auto_flush())

    def _map_event(self, event: Any) -> dict[str, Any]:
        """Map an AuditEvent to the server EventPayload format."""
        return {
            "call_id": event.call_id,
            "agent_id": self._client.agent_id,
            "tool_name": event.tool_name,
            "verdict": event.action.value,
            "mode": event.mode,
            "timestamp": event.timestamp.isoformat(),
            "payload": {
                "tool_args": event.tool_args,
                "side_effect": event.side_effect,
                "environment": getattr(event, "environment", None) or self._client.env,
                "principal": event.principal,
                "decision_source": event.decision_source,
                "decision_name": event.decision_name,
                "reason": event.reason,
                "policy_version": event.policy_version,
                "bundle_name": self._client.bundle_name,
            },
        }

    async def flush(self) -> None:
        """Flush all buffered events to the server."""
        async with self._lock:
            await self._flush_locked()

    async def _flush_locked(self) -> None:
        """Flush buffer while lock is held."""
        if not self._buffer:
            return
        events = list(self._buffer)
        try:
            await self._client.post("/api/v1/events", {"events": events})
            self._buffer.clear()
        except Exception:
            logger.warning("Failed to flush %d audit events, keeping in buffer for retry", len(events))
            if len(self._buffer) > self._max_buffer_size:
                dropped = len(self._buffer) - self._max_buffer_size
                self._buffer = self._buffer[dropped:]
                logger.warning("Buffer exceeded %d, dropped %d oldest events", self._max_buffer_size, dropped)

    async def _auto_flush(self) -> None:
        """Background task: flush after flush_interval seconds."""
        await asyncio.sleep(self._flush_interval)
        await self.flush()

    async def close(self) -> None:
        """Flush remaining events and cancel the background flush task."""
        if self._flush_task is not None and not self._flush_task.done():
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        await self.flush()

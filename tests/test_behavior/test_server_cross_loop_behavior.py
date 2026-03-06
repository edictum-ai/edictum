"""Behavior tests for thread-local client and thread-safe audit sink.

Verifies the cross-event-loop fix mechanics using mocks — no real HTTP.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from edictum.audit import AuditAction, AuditEvent
from edictum.server.audit_sink import ServerAuditSink
from edictum.server.client import EdictumServerClient


def _make_client() -> EdictumServerClient:
    return EdictumServerClient("https://example.com", "test-key", agent_id="agent-1")


def _run_in_thread(coro_factory):
    """Run an async function in a new thread via asyncio.run().

    Returns whatever the coroutine returns.
    """
    result = None
    error = None

    def target():
        nonlocal result, error
        try:
            result = asyncio.run(coro_factory())
        except Exception as exc:
            error = exc

    t = threading.Thread(target=target)
    t.start()
    t.join(timeout=5)
    if error is not None:
        raise error
    return result


def _make_audit_event(call_id: str = "call-1") -> AuditEvent:
    return AuditEvent(
        call_id=call_id,
        tool_name="read_file",
        action=AuditAction.CALL_ALLOWED,
        mode="enforce",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        tool_args={"path": "/tmp/test"},
        side_effect="read_only",
        environment="production",
        principal=None,
        decision_source="precondition",
        decision_name="allow_reads",
        reason=None,
        policy_version="abc123",
    )


def _make_mock_sink_client() -> MagicMock:
    client = MagicMock(spec=EdictumServerClient)
    client.agent_id = "test-agent"
    client.env = "production"
    client.bundle_name = "default"
    client.post = AsyncMock(return_value={"accepted": 1, "duplicates": 0})
    return client


class TestClientThreadLocal:
    """Thread-local httpx.AsyncClient isolation."""

    @pytest.mark.asyncio
    async def test_different_threads_get_different_clients(self):
        """Each thread gets its own httpx.AsyncClient instance."""
        client = _make_client()
        main_http = client._ensure_client()
        main_id = id(main_http)

        async def worker():
            return id(client._ensure_client())

        worker_id = _run_in_thread(worker)
        assert main_id != worker_id
        await client.close()

    @pytest.mark.asyncio
    async def test_same_thread_same_loop_reuses_client(self):
        """Repeated calls on the same thread+loop return the same client."""
        client = _make_client()
        http1 = client._ensure_client()
        http2 = client._ensure_client()
        assert http1 is http2
        await client.close()

    @pytest.mark.asyncio
    async def test_loop_mismatch_creates_fresh_client(self):
        """When stored loop object differs (thread reuse), a fresh client is created."""
        client = _make_client()
        http1 = client._ensure_client()

        # Simulate thread reuse with a new loop by setting a dummy loop ref
        client._local.loop = object()

        http2 = client._ensure_client()
        assert http1 is not http2
        await client.close()

    @pytest.mark.asyncio
    async def test_close_only_affects_calling_thread(self):
        """close() on main thread does not affect worker thread clients."""
        client = _make_client()
        client._ensure_client()

        # Create a client on a worker thread
        async def worker_ensure():
            client._ensure_client()

        _run_in_thread(worker_ensure)

        # Close main thread's client
        await client.close()
        assert getattr(client._local, "client", None) is None

        # Worker thread can still get a fresh client
        async def worker_check():
            http = client._ensure_client()
            return http is not None

        assert _run_in_thread(worker_check) is True

    @pytest.mark.asyncio
    async def test_aenter_client_reused_by_ensure_client(self):
        """__aenter__ sets loop ref so _ensure_client reuses the same instance."""
        client = _make_client()
        async with client as c:
            aenter_http = getattr(c._local, "client", None)
            ensure_http = c._ensure_client()
            assert aenter_http is ensure_http


class TestAuditSinkThreading:
    """Thread-safe buffer access in ServerAuditSink."""

    @pytest.mark.asyncio
    async def test_audit_sink_emit_from_multiple_threads(self):
        """Events emitted from multiple threads all land in the buffer."""
        mock_client = _make_mock_sink_client()
        sink = ServerAuditSink(mock_client, batch_size=100, flush_interval=999)

        events_per_thread = 10
        num_threads = 3

        async def worker(thread_idx: int):
            for i in range(events_per_thread):
                await sink.emit(_make_audit_event(call_id=f"t{thread_idx}-{i}"))

        threads = []
        for idx in range(num_threads):
            t_idx = idx

            def target(ti=t_idx):
                asyncio.run(worker(ti))

            t = threading.Thread(target=target)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=5)

        assert len(sink._buffer) == events_per_thread * num_threads

    @pytest.mark.asyncio
    async def test_audit_sink_flush_releases_lock_during_io(self):
        """Lock is NOT held during the network POST (I/O outside lock)."""
        mock_client = _make_mock_sink_client()
        sink = ServerAuditSink(mock_client, batch_size=100, flush_interval=999)

        lock_acquired_during_post = threading.Event()

        original_post = mock_client.post

        async def slow_post(*args, **kwargs):
            # While POST is "in flight", try acquiring the lock from another thread
            def try_lock():
                acquired = sink._lock.acquire(timeout=1)
                if acquired:
                    lock_acquired_during_post.set()
                    sink._lock.release()

            t = threading.Thread(target=try_lock)
            t.start()
            t.join(timeout=2)
            return await original_post(*args, **kwargs)

        mock_client.post = slow_post

        await sink.emit(_make_audit_event())
        await sink.flush()

        assert lock_acquired_during_post.is_set(), "Lock should be free during POST"

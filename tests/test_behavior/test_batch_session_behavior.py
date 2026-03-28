"""Behavior tests for batch session counter reads.

Verifies that batch_get() on backends and batch_get_counters() on Session
reduce the number of storage round trips, and that the pipeline uses
batched reads for session counter checks.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from edictum import Edictum, create_envelope
from edictum.pipeline import CheckPipeline
from edictum.server.backend import ServerBackend
from edictum.server.client import EdictumServerError
from edictum.session import Session
from edictum.storage import MemoryBackend

# ---------------------------------------------------------------------------
# MemoryBackend.batch_get
# ---------------------------------------------------------------------------


class TestMemoryBackendBatchGet:
    async def test_returns_correct_values(self):
        """batch_get returns the stored values for each key."""
        backend = MemoryBackend()
        await backend.set("k1", "v1")
        await backend.increment("k2", amount=5)

        result = await backend.batch_get(["k1", "k2"])
        assert result["k1"] == "v1"
        assert result["k2"] == "5"

    async def test_missing_keys_return_none(self):
        """Keys that don't exist return None in the result dict."""
        backend = MemoryBackend()
        await backend.set("exists", "yes")

        result = await backend.batch_get(["exists", "missing1", "missing2"])
        assert result["exists"] == "yes"
        assert result["missing1"] is None
        assert result["missing2"] is None

    async def test_empty_keys_returns_empty_dict(self):
        """An empty key list returns an empty dict."""
        backend = MemoryBackend()
        result = await backend.batch_get([])
        assert result == {}


# ---------------------------------------------------------------------------
# ServerBackend.batch_get
# ---------------------------------------------------------------------------


class TestServerBackendBatchGet:
    @pytest.mark.asyncio
    async def test_single_post_call(self):
        """batch_get makes a single POST to /api/v1/sessions/batch."""
        client = MagicMock()
        client.post = AsyncMock(return_value={"values": {"k1": "v1", "k2": "v2"}})
        backend = ServerBackend(client)

        result = await backend.batch_get(["k1", "k2"])

        client.post.assert_called_once_with(
            "/api/v1/sessions/batch",
            {"keys": ["k1", "k2"]},
        )
        assert result == {"k1": "v1", "k2": "v2"}

    @pytest.mark.asyncio
    async def test_missing_keys_return_none(self):
        """Keys not in the server response are returned as None."""
        client = MagicMock()
        client.post = AsyncMock(return_value={"values": {"k1": "v1"}})
        backend = ServerBackend(client)

        result = await backend.batch_get(["k1", "k2"])
        assert result["k1"] == "v1"
        assert result["k2"] is None

    @pytest.mark.asyncio
    async def test_empty_keys_returns_empty_dict_no_http(self):
        """Empty key list returns empty dict without making any HTTP call."""
        client = MagicMock()
        client.post = AsyncMock()
        backend = ServerBackend(client)

        result = await backend.batch_get([])
        assert result == {}
        client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_fallback_on_404(self):
        """Falls back to individual get() calls when server returns 404."""
        client = MagicMock()
        client.post = AsyncMock(side_effect=EdictumServerError(404, "Not Found"))
        client.get = AsyncMock(
            side_effect=[
                {"value": "v1"},
                EdictumServerError(404, "Not Found"),
            ]
        )
        backend = ServerBackend(client)

        result = await backend.batch_get(["k1", "k2"])
        assert result["k1"] == "v1"
        assert result["k2"] is None
        # Verify individual gets were called
        assert client.get.call_count == 2

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_raises_on_500(self):
        """Non-404 server errors propagate (fail-closed)."""
        client = MagicMock()
        client.post = AsyncMock(side_effect=EdictumServerError(500, "Internal Server Error"))
        backend = ServerBackend(client)

        with pytest.raises(EdictumServerError, match="HTTP 500"):
            await backend.batch_get(["k1"])

    @pytest.mark.asyncio
    @pytest.mark.security
    async def test_raises_on_connection_error(self):
        """Connection errors propagate (fail-closed)."""
        client = MagicMock()
        client.post = AsyncMock(side_effect=ConnectionError("refused"))
        backend = ServerBackend(client)

        with pytest.raises(ConnectionError, match="refused"):
            await backend.batch_get(["k1"])


# ---------------------------------------------------------------------------
# Session.batch_get_counters
# ---------------------------------------------------------------------------


class TestSessionBatchGetCounters:
    async def test_returns_attempts_and_execs(self):
        """batch_get_counters returns attempt and execution counts."""
        backend = MemoryBackend()
        session = Session("s1", backend)
        await session.increment_attempts()
        await session.increment_attempts()
        await session.record_execution("Bash", success=True)

        counters = await session.batch_get_counters()
        assert counters["attempts"] == 2
        assert counters["execs"] == 1

    async def test_includes_tool_count_when_requested(self):
        """include_tool adds the per-tool counter to the result."""
        backend = MemoryBackend()
        session = Session("s1", backend)
        await session.record_execution("Bash", success=True)
        await session.record_execution("Bash", success=True)
        await session.record_execution("Read", success=True)

        counters = await session.batch_get_counters(include_tool="Bash")
        assert counters["tool:Bash"] == 2
        assert counters["execs"] == 3

    async def test_missing_tool_returns_zero(self):
        """A tool with no executions returns 0."""
        backend = MemoryBackend()
        session = Session("s1", backend)

        counters = await session.batch_get_counters(include_tool="NoSuchTool")
        assert counters["tool:NoSuchTool"] == 0

    async def test_zero_counters_on_fresh_session(self):
        """A fresh session returns all zeros."""
        backend = MemoryBackend()
        session = Session("s1", backend)

        counters = await session.batch_get_counters()
        assert counters["attempts"] == 0
        assert counters["execs"] == 0

    async def test_falls_back_without_batch_get(self):
        """Works with backends that lack batch_get (individual gets)."""

        class MinimalBackend:
            """Backend without batch_get -- only implements the Protocol."""

            def __init__(self):
                self._data: dict[str, str] = {}

            async def get(self, key: str) -> str | None:
                return self._data.get(key)

            async def set(self, key: str, value: str) -> None:
                self._data[key] = value

            async def delete(self, key: str) -> None:
                self._data.pop(key, None)

            async def increment(self, key: str, amount: float = 1) -> float:
                cur = float(self._data.get(key, "0"))
                cur += amount
                self._data[key] = str(int(cur)) if cur == int(cur) else str(cur)
                return cur

        backend = MinimalBackend()
        session = Session("s1", backend)

        # Manually set some counter values
        await backend.increment("s:s1:attempts", 3)
        await backend.increment("s:s1:execs", 2)

        counters = await session.batch_get_counters()
        assert counters["attempts"] == 3
        assert counters["execs"] == 2

    async def test_uses_batch_get_when_available(self):
        """Verifies batch_get is called instead of individual get() calls
        at the Session layer (batch_get itself may delegate to get())."""
        backend = MemoryBackend()
        session = Session("s1", backend)

        with patch.object(backend, "batch_get", wraps=backend.batch_get) as mock_batch:
            await session.batch_get_counters(include_tool="Bash")
            # Session should call batch_get once with all keys
            mock_batch.assert_called_once()
            keys_arg = mock_batch.call_args[0][0]
            assert len(keys_arg) == 3  # attempts, execs, tool:Bash


# ---------------------------------------------------------------------------
# Pipeline integration: batch read reduces round trips
# ---------------------------------------------------------------------------


class TestPipelineBatchIntegration:
    async def test_pipeline_uses_batch_counters(self, null_sink, backend):
        """Pipeline pre_execute uses batch_get_counters instead of
        individual session counter reads."""
        guard = Edictum(
            environment="test",
            audit_sink=null_sink,
            backend=backend,
        )
        session = Session("s1", backend)
        tool_call = create_envelope("Bash", {"command": "ls"})

        with patch.object(session, "batch_get_counters", wraps=session.batch_get_counters) as mock_batch:
            pipeline = CheckPipeline(guard)
            decision = await pipeline.pre_execute(tool_call, session)

            # batch_get_counters should have been called once
            mock_batch.assert_called_once()
            assert decision.action == "allow"

    async def test_pipeline_batches_tool_key_when_per_tool_limit_set(self, null_sink, backend):
        """When per-tool limits are configured, the tool key is included
        in the batch fetch."""
        guard = Edictum(
            environment="test",
            audit_sink=null_sink,
            backend=backend,
        )
        guard.limits.max_calls_per_tool["Bash"] = 5
        session = Session("s1", backend)
        tool_call = create_envelope("Bash", {"command": "ls"})

        with patch.object(session, "batch_get_counters", wraps=session.batch_get_counters) as mock_batch:
            pipeline = CheckPipeline(guard)
            await pipeline.pre_execute(tool_call, session)

            mock_batch.assert_called_once_with(include_tool="Bash")

    async def test_pipeline_does_not_batch_tool_key_when_no_per_tool_limit(self, null_sink, backend):
        """Without per-tool limits, no tool key is batched."""
        guard = Edictum(
            environment="test",
            audit_sink=null_sink,
            backend=backend,
        )
        session = Session("s1", backend)
        tool_call = create_envelope("Bash", {"command": "ls"})

        with patch.object(session, "batch_get_counters", wraps=session.batch_get_counters) as mock_batch:
            pipeline = CheckPipeline(guard)
            await pipeline.pre_execute(tool_call, session)

            mock_batch.assert_called_once_with(include_tool=None)
